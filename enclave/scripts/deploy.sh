#!/usr/bin/env bash
# Deploys the Seal stack (enclave/deploy/seal-stack.template.json) to each
# region of enclave/deploy/regions.json, one stack per region, in list order:
# the genesis region first, then each region joining from its peer.
#
# Without --apply it only prints the commands it would run and runs nothing
# (no AWS account or credentials needed). With --apply it runs them with the
# aws CLI.
#
#   bash enclave/scripts/deploy.sh [--apply] \
#     --eif-url REGION=URL --eif-sha256 REGION=HEX (once each per region) \
#     --proxy-url URL --proxy-sha256 HEX --measurements-url URL \
#     --measurements-sha256 HEX --ghost-node HOST:PORT --ghost-node-2 HOST:PORT
#
# Each region runs its own image (its region id is compiled in, see
# compute-pcrs.sh), so each region of regions.json gets its own EIF URL and
# SHA-256: one --eif-url and one --eif-sha256 per region. It refuses when any
# region's is missing (with --apply, or when only some are given), a region
# not in regions.json, a region given twice, and one EIF given to two regions.
#
# The two Ghost nodes are the two entries of the Seal's compiled-in release
# node list (seal/src/node_list.rs), in its order: the host carries the
# enclave's vsock port 5003 to the first and 5004 to the second.
#
# Genesis happens once, ever: if the genesis region's stack already exists,
# it is deployed in join mode from the next region in the list, so no later
# start makes a new M.
#
# regions.json must list exactly the region list compiled into the image
# (RELEASE_REGIONS in seal/src/journal_anchor.rs), in its order. Each stack
# gets the two other regions, in that order, as its journal anchor peers:
# the enclave's vsock port 5006 goes to the first one's proxy, 5007 to the
# second's. A region deployed before a later one existed is deployed again
# at the end with every peer's address (its host is replaced; it joins M
# from a running region and restores its journal from a peer).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
template="$repo/enclave/deploy/seal-stack.template.json"
regions="$repo/enclave/deploy/regions.json"

usage() {
  sed -n '2,35p' "${BASH_SOURCE[0]}" >&2
  exit 2
}

apply=0
proxy_url="" proxy_sha256="" measurements_url="" measurements_sha256="" ghost_node="" ghost_node_2=""
# The --eif-url and --eif-sha256 values as given: REGION=VALUE each.
eif_url_args=() eif_sha256_args=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --apply) apply=1; shift ;;
    --eif-url) eif_url_args+=("${2:-}"); shift 2 || usage ;;
    --eif-sha256) eif_sha256_args+=("${2:-}"); shift 2 || usage ;;
    --proxy-url) proxy_url="${2:-}"; shift 2 || usage ;;
    --proxy-sha256) proxy_sha256="${2:-}"; shift 2 || usage ;;
    --measurements-url) measurements_url="${2:-}"; shift 2 || usage ;;
    --measurements-sha256) measurements_sha256="${2:-}"; shift 2 || usage ;;
    --ghost-node) ghost_node="${2:-}"; shift 2 || usage ;;
    --ghost-node-2) ghost_node_2="${2:-}"; shift 2 || usage ;;
    -h | --help) usage ;;
    *) echo "deploy: unknown argument $1" >&2; usage ;;
  esac
done

command -v jq > /dev/null || { echo "deploy: needs jq" >&2; exit 2; }
if [ "$apply" = 1 ]; then
  command -v aws > /dev/null || { echo "deploy: --apply needs the aws CLI" >&2; exit 2; }
  for value in "$proxy_url" "$proxy_sha256" "$measurements_url" "$measurements_sha256" "$ghost_node" "$ghost_node_2"; do
    [ -n "$value" ] || { echo "deploy: --apply needs every --proxy, --measurements, --ghost-node and --ghost-node-2 value" >&2; exit 2; }
  done
  [ "$ghost_node" != "$ghost_node_2" ] || { echo "deploy: --ghost-node and --ghost-node-2 are the list's two nodes, not one" >&2; exit 2; }
else
  echo "# deploy: printing only; nothing is run (add --apply to run)."
  : "${proxy_url:=<proxy-url>}" "${proxy_sha256:=<proxy-sha256>}"
  : "${measurements_url:=<measurements-url>}" "${measurements_sha256:=<measurements-sha256>}" "${ghost_node:=<ghost-node>}"
  : "${ghost_node_2:=<ghost-node-2>}"
fi

# Runs a command, or prints it.
run() {
  if [ "$apply" = 1 ]; then
    "$@"
  else
    printf '%q ' "$@"
    printf '\n'
  fi
}

# Prints a lookup's result; without --apply, prints the lookup and a placeholder.
lookup() {
  local placeholder="$1"
  shift
  if [ "$apply" = 1 ]; then
    "$@"
  else
    printf '# would look up %s with: %s\n' "$placeholder" "$*" >&2
    printf '%s' "$placeholder"
  fi
}

stack_exists() {
  [ "$apply" = 1 ] && aws cloudformation describe-stacks --region "$1" --stack-name "$2" > /dev/null 2>&1
}

prefix="$(jq -r '.stackPrefix' "$regions")"
count="$(jq '.regions | length' "$regions")"
if [ "$count" -lt 2 ] || [ "$count" -gt 3 ]; then
  echo "deploy: regions.json lists $count regions; it must list 2 or 3" >&2
  exit 1
fi
# The image's compiled-in region list: each card's home region is computed
# over it, so regions.json must be the same list in the same order.
compiled="$(grep -o 'RELEASE_REGIONS: \[&str; [0-9]*] = \[[^]]*]' "$repo/seal/src/journal_anchor.rs" |
  grep -o '"[a-z0-9-]*"' | tr -d '"' | paste -sd, -)"
listed="$(jq -r '[.regions[].region] | join(",")' "$regions")"
if [ "$compiled" != "$listed" ]; then
  echo "deploy: regions.json lists $listed; the image has $compiled compiled in" >&2
  exit 1
fi

# Each region's own EIF: eif_urls[i] and eif_hashes[i] for regions.json's
# region i, from the REGION=VALUE arguments.
region_names=()
for index in $(seq 0 $((count - 1))); do
  region_names+=("$(jq -r ".regions[$index].region" "$regions")")
done
eif_urls=() eif_hashes=()
for index in "${!region_names[@]}"; do
  eif_urls[index]="" eif_hashes[index]=""
done

# Index of region $1 in regions.json; fails for any other.
region_index() {
  local index
  for index in "${!region_names[@]}"; do
    if [ "${region_names[index]}" = "$1" ]; then
      printf '%s' "$index"
      return 0
    fi
  done
  return 1
}

# Takes one REGION=VALUE argument of flag $1 into the array named $2.
take_eif() {
  local flag="$1" into="$2" arg="$3" region value index
  if [[ "$arg" != *=* ]]; then
    echo "deploy: $flag takes REGION=VALUE, one per region of regions.json (each region runs its own image), not '$arg'" >&2
    exit 2
  fi
  region="${arg%%=*}" value="${arg#*=}"
  if ! index="$(region_index "$region")"; then
    echo "deploy: $flag names $region, which is not in regions.json (${region_names[*]})" >&2
    exit 2
  fi
  if [ -z "$value" ]; then
    echo "deploy: $flag $region= has no value" >&2
    exit 2
  fi
  if [ "$into" = eif_urls ]; then
    [ -z "${eif_urls[index]}" ] || { echo "deploy: $flag gives $region twice" >&2; exit 2; }
    [[ "$value" =~ ^https://.+ ]] || { echo "deploy: $flag $region: the URL must be https://" >&2; exit 2; }
    eif_urls[index]="$value"
  else
    [ -z "${eif_hashes[index]}" ] || { echo "deploy: $flag gives $region twice" >&2; exit 2; }
    [[ "$value" =~ ^[0-9a-f]{64}$ ]] || { echo "deploy: $flag $region: the SHA-256 must be 64 lowercase hex digits" >&2; exit 2; }
    eif_hashes[index]="$value"
  fi
}

for arg in ${eif_url_args[@]+"${eif_url_args[@]}"}; do
  take_eif --eif-url eif_urls "$arg"
done
for arg in ${eif_sha256_args[@]+"${eif_sha256_args[@]}"}; do
  take_eif --eif-sha256 eif_hashes "$arg"
done

# Every region's EIF, or (printing only, with none given) placeholders.
given=$((${#eif_url_args[@]} + ${#eif_sha256_args[@]}))
if [ "$apply" = 0 ] && [ "$given" = 0 ]; then
  for index in "${!region_names[@]}"; do
    eif_urls[index]="<eif-url-of-${region_names[index]}>"
    eif_hashes[index]="<eif-sha256-of-${region_names[index]}>"
  done
else
  for index in "${!region_names[@]}"; do
    if [ -z "${eif_urls[index]}" ] || [ -z "${eif_hashes[index]}" ]; then
      echo "deploy: no EIF for ${region_names[index]}: give --eif-url ${region_names[index]}=URL and --eif-sha256 ${region_names[index]}=HEX (one of each per region of regions.json)" >&2
      exit 2
    fi
  done
  # One image per region: the same EIF in two regions would run one
  # region's id in the other.
  for index in "${!region_names[@]}"; do
    for other in "${!region_names[@]}"; do
      [ "$other" -gt "$index" ] || continue
      if [ "${eif_hashes[index]}" = "${eif_hashes[other]}" ] || [ "${eif_urls[index]}" = "${eif_urls[other]}" ]; then
        echo "deploy: ${region_names[index]} and ${region_names[other]} are given the same EIF; each region runs its own image" >&2
        exit 2
      fi
    done
  done
fi

# The ProxyAddress of region $1's stack; nothing when it does not exist yet.
anchor_address() {
  if [ "$apply" = 1 ] && ! stack_exists "$1" "$prefix-$1"; then
    return 0
  fi
  lookup "<ProxyAddress of $prefix-$1>" aws cloudformation describe-stacks \
    --region "$1" --stack-name "$prefix-$1" \
    --query "Stacks[0].Outputs[?OutputKey=='ProxyAddress'].OutputValue" --output text
}

# Regions deployed without the address of every anchor peer.
missing=()

deploy_region() {
  local index="$1" region start peer stack peer_address vpc subnet anchor anchor_2 other
  local others=()
  region="$(jq -r ".regions[$index].region" "$regions")"
  start="$(jq -r ".regions[$index].start" "$regions")"
  peer="$(jq -r ".regions[$index].peer // \"\"" "$regions")"
  stack="$prefix-$region"

  if [ "$start" = genesis ]; then
    if stack_exists "$region" "$stack"; then
      start="join"
      peer="$(jq -r ".regions[] | select(.start != \"genesis\") | .region" "$regions" | head -n 1)"
      echo "# $stack exists: deploying it in join mode from $peer (genesis happens once)."
    elif [ "$apply" = 0 ]; then
      echo "# $region: genesis only if $stack does not exist yet; otherwise join from the next region."
    fi
  fi

  peer_address=""
  if [ "$start" = join ]; then
    peer_address="$(lookup "<ProxyAddress of $prefix-$peer>" aws cloudformation describe-stacks \
      --region "$peer" --stack-name "$prefix-$peer" \
      --query "Stacks[0].Outputs[?OutputKey=='ProxyAddress'].OutputValue" --output text)"
  fi
  vpc="$(lookup "<default VPC of $region>" aws ec2 describe-vpcs --region "$region" \
    --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
  subnet="$(lookup "<a default subnet of $region>" aws ec2 describe-subnets --region "$region" \
    --filters "Name=vpc-id,Values=$vpc" Name=default-for-az,Values=true --query 'Subnets[0].SubnetId' --output text)"

  # The journal anchor peers: the other regions in list order, vsock ports
  # 5006 and 5007.
  for other in $(jq -r '.regions[].region' "$regions"); do
    [ "$other" = "$region" ] || others+=("$other")
  done
  anchor="$(anchor_address "${others[0]}")"
  anchor_2="$(anchor_address "${others[1]}")"
  if [ -z "$anchor" ] || [ -z "$anchor_2" ]; then
    missing+=("$index")
  fi

  echo "# $region: $stack, $start${peer:+ from $peer}; journal anchored in ${others[0]} (5006) and ${others[1]} (5007); its own EIF ${eif_hashes[index]}"
  run aws cloudformation deploy \
    --region "$region" \
    --stack-name "$stack" \
    --template-file "$template" \
    --capabilities CAPABILITY_IAM \
    --no-fail-on-empty-changeset \
    --parameter-overrides \
    "VpcId=$vpc" \
    "SubnetId=$subnet" \
    "EifUrl=${eif_urls[index]}" \
    "EifSha256=${eif_hashes[index]}" \
    "ProxyUrl=$proxy_url" \
    "ProxySha256=$proxy_sha256" \
    "MeasurementsUrl=$measurements_url" \
    "MeasurementsSha256=$measurements_sha256" \
    "GhostNodeAddress=$ghost_node" \
    "GhostNodeAddress2=$ghost_node_2" \
    "StartMode=$start" \
    "PeerAddress=$peer_address" \
    "AnchorPeerRegion=${others[0]}" \
    "AnchorPeerRegion2=${others[1]}" \
    "AnchorPeerAddress=$anchor" \
    "AnchorPeerAddress2=$anchor_2"
}

for index in $(seq 0 $((count - 1))); do
  deploy_region "$index"
done

# A region deployed before a later peer existed has no address for it: it
# serves no Fill or Open until it is deployed again with every address.
if [ "${#missing[@]}" -gt 0 ]; then
  again=("${missing[@]}")
  missing=()
  echo "# again, now that every region exists: each with both anchor peers' addresses."
  for index in "${again[@]}"; do
    deploy_region "$index"
  done
elif [ "$apply" = 0 ]; then
  echo "# with --apply, a region deployed before a later peer existed is deployed again at the end with its address."
fi
