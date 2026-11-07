#!/usr/bin/env bash
# Deploys the Seal stack (enclave/deploy/seal-stack.template.json) to each
# region of enclave/deploy/regions.json, one stack per region, in list order:
# the genesis region first, then each region joining from its peer.
#
# Without --apply it only prints the commands it would run and runs nothing
# (no AWS account or credentials needed). With --apply it runs them with the
# aws CLI.
#
#   bash enclave/scripts/deploy.sh [--apply] --eif-url URL --eif-sha256 HEX \
#     --proxy-url URL --proxy-sha256 HEX --measurements-url URL \
#     --measurements-sha256 HEX --ghost-node HOST:PORT --ghost-node-2 HOST:PORT
#
# The two Ghost nodes are the two entries of the Seal's compiled-in release
# node list (seal/src/node_list.rs), in its order: the host carries the
# enclave's vsock port 5003 to the first and 5004 to the second.
#
# Genesis happens once, ever: if the genesis region's stack already exists,
# it is deployed in join mode from the next region in the list, so no later
# start makes a new M.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
template="$repo/enclave/deploy/seal-stack.template.json"
regions="$repo/enclave/deploy/regions.json"

usage() {
  sed -n '2,20p' "${BASH_SOURCE[0]}" >&2
  exit 2
}

apply=0
eif_url="" eif_sha256="" proxy_url="" proxy_sha256="" measurements_url="" measurements_sha256="" ghost_node="" ghost_node_2=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --apply) apply=1; shift ;;
    --eif-url) eif_url="${2:-}"; shift 2 || usage ;;
    --eif-sha256) eif_sha256="${2:-}"; shift 2 || usage ;;
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
  for value in "$eif_url" "$eif_sha256" "$proxy_url" "$proxy_sha256" "$measurements_url" "$measurements_sha256" "$ghost_node" "$ghost_node_2"; do
    [ -n "$value" ] || { echo "deploy: --apply needs every --eif, --proxy, --measurements, --ghost-node and --ghost-node-2 value" >&2; exit 2; }
  done
  [ "$ghost_node" != "$ghost_node_2" ] || { echo "deploy: --ghost-node and --ghost-node-2 are the list's two nodes, not one" >&2; exit 2; }
else
  echo "# deploy: printing only; nothing is run (add --apply to run)."
  : "${eif_url:=<eif-url>}" "${eif_sha256:=<eif-sha256>}" "${proxy_url:=<proxy-url>}" "${proxy_sha256:=<proxy-sha256>}"
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

for index in $(seq 0 $((count - 1))); do
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

  echo "# $region: $stack, $start${peer:+ from $peer}"
  run aws cloudformation deploy \
    --region "$region" \
    --stack-name "$stack" \
    --template-file "$template" \
    --capabilities CAPABILITY_IAM \
    --no-fail-on-empty-changeset \
    --parameter-overrides \
    "VpcId=$vpc" \
    "SubnetId=$subnet" \
    "EifUrl=$eif_url" \
    "EifSha256=$eif_sha256" \
    "ProxyUrl=$proxy_url" \
    "ProxySha256=$proxy_sha256" \
    "MeasurementsUrl=$measurements_url" \
    "MeasurementsSha256=$measurements_sha256" \
    "GhostNodeAddress=$ghost_node" \
    "GhostNodeAddress2=$ghost_node_2" \
    "StartMode=$start" \
    "PeerAddress=$peer_address"
done
