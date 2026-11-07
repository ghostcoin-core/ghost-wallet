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
#
# With --apply, after each stack's create or update it waits (at most
# DEPLOY_START_WAIT seconds, 900 by default, looking every DEPLOY_START_POLL
# seconds, 15 by default) for the start outcome of the stack's current host
# in its log group /ghost-seal/<stack>: "ok: made M (genesis)" or "ok:
# received M from a running enclave". On any "refused:" line, or when the
# wait runs out, it stops at once with that line and deploys nothing more.
# A region holds M and serves when its stack is complete, its host runs and
# that host logged that it holds M. The second pass runs only once every
# region holds M, one region at a time, each only once two other regions
# hold M and serve. An existing stack whose host holds M is replaced only
# then too (otherwise it is left as it is until the second pass), and one
# whose host may hold M only while another region holds M: a region that
# may be the only M holder is never replaced.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
template="$repo/enclave/deploy/seal-stack.template.json"
regions="$repo/enclave/deploy/regions.json"

usage() {
  sed -n '2,49p' "${BASH_SOURCE[0]}" >&2
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
# How long to wait for each host's start outcome, and how often to look.
start_wait="${DEPLOY_START_WAIT:-900}" start_poll="${DEPLOY_START_POLL:-15}"
[[ "$start_wait" =~ ^[1-9][0-9]*$ ]] || { echo "deploy: DEPLOY_START_WAIT is a whole number of seconds, not '$start_wait'" >&2; exit 2; }
[[ "$start_poll" =~ ^[0-9]+(\.[0-9]+)?$ ]] || { echo "deploy: DEPLOY_START_POLL is a number of seconds, not '$start_poll'" >&2; exit 2; }
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

# The two lines an enclave logs once it holds M (seal_enclave's start answer,
# which seal_proxy start writes to the host's log as "the enclave answered").
made_m="ok: made M (genesis)"
received_m="ok: received M from a running enclave"
# Why the last check of holds_m or two_others_hold_m failed.
why=""
# The count other_holders found.
holders=0

# The status of region $1's stack; nothing when it does not exist.
stack_status() {
  [ "$apply" = 1 ] && aws cloudformation describe-stacks --region "$1" --stack-name "$prefix-$1" \
    --query 'Stacks[0].StackStatus' --output text 2> /dev/null || true
}

# The instance id of region $1's current host; nothing when there is none.
stack_instance() {
  local instance
  instance="$([ "$apply" = 1 ] && aws cloudformation describe-stacks --region "$1" --stack-name "$prefix-$1" \
    --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue" --output text 2> /dev/null || true)"
  [ "$instance" = None ] || printf '%s' "$instance"
}

# The state (running, stopped, ...) of host $2 in region $1.
instance_state() {
  [ "$apply" = 1 ] && aws ec2 describe-instances --region "$1" --instance-ids "$2" \
    --query 'Reservations[0].Instances[0].State.Name' --output text 2> /dev/null || true
}

# The start outcome host $2 of region $1 logged in /ghost-seal/<stack>, from
# its own log stream only (a replaced host's stream keeps its old lines):
# "refused <line>" when it logged any refused: line, else "ok <line>" when
# it logged that it holds M, else "none".
start_outcome() {
  local lines line
  lines="$([ "$apply" = 1 ] && aws logs filter-log-events --region "$1" --log-group-name "/ghost-seal/$prefix-$1" \
    --log-stream-names "$2" --query 'events[].message' --output json 2> /dev/null |
    jq -r '.[]?' 2> /dev/null || true)"
  line="$(printf '%s\n' "$lines" | grep -F -m 1 'refused:' || true)"
  if [ -n "$line" ]; then
    printf 'refused %s' "$line"
    return 0
  fi
  line="$(printf '%s\n' "$lines" | grep -F -m 1 -e "$made_m" -e "$received_m" || true)"
  if [ -n "$line" ]; then
    printf 'ok %s' "$line"
  else
    printf 'none'
  fi
}

# Whether region $1 holds M and serves: its stack is complete, its current
# host runs, and that host logged that it holds M and no refusal. Sets why
# when it does not.
holds_m() {
  local region="$1" status instance state outcome
  status="$(stack_status "$region")"
  case "$status" in
    CREATE_COMPLETE | UPDATE_COMPLETE | UPDATE_ROLLBACK_COMPLETE) ;;
    "") why="$region has no stack"; return 1 ;;
    *) why="$region's stack is $status"; return 1 ;;
  esac
  instance="$(stack_instance "$region")"
  if [ -z "$instance" ]; then
    why="$region's stack names no host"
    return 1
  fi
  state="$(instance_state "$region" "$instance")"
  if [ "$state" != running ]; then
    why="$region's host $instance is ${state:-not found}"
    return 1
  fi
  outcome="$(start_outcome "$region" "$instance")"
  case "$outcome" in
    ok\ *) return 0 ;;
    refused\ *) why="$region's host $instance logged ${outcome#refused }"; return 1 ;;
    *) why="$region's host $instance has not logged that it holds M"; return 1 ;;
  esac
}

# How many regions other than $1 hold M and serve; why says which do not.
other_holders() {
  local region="$1" other count=0 reasons=""
  for other in "${region_names[@]}"; do
    [ "$other" != "$region" ] || continue
    if holds_m "$other"; then
      count=$((count + 1))
    else
      reasons="${reasons:+$reasons; }$why"
    fi
  done
  why="$reasons"
  holders="$count"
}

# Succeeds once at least two regions other than $1 hold M and serve, checked
# just now; sets why when fewer do.
two_others_hold_m() {
  other_holders "$1"
  if [ "$holders" -ge 2 ]; then
    echo "# $1: $holders other regions hold M and serve, checked just now."
    return 0
  fi
  why="only $holders other region(s) hold M and serve: $why"
  return 1
}

# Waits for the start outcome of region $1's current host, at most
# start_wait seconds. Stops the whole run, deploying nothing more, on any
# refused: line or when the wait runs out.
wait_for_m() {
  local region="$1" stack="$prefix-$1" instance outcome deadline
  if [ "$apply" = 0 ]; then
    echo "# then wait up to ${start_wait}s for $stack's host to log \"$made_m\" or \"$received_m\" in /ghost-seal/$stack; stop, deploying nothing more, on any refused: line or at the end of the wait."
    return 0
  fi
  instance="$(stack_instance "$region")"
  if [ -z "$instance" ]; then
    echo "deploy: $stack names no host (no InstanceId output); stopped, nothing more is deployed" >&2
    exit 1
  fi
  echo "# $region: waiting up to ${start_wait}s for host $instance to log its start in /ghost-seal/$stack."
  deadline=$((SECONDS + start_wait))
  while :; do
    outcome="$(start_outcome "$region" "$instance")"
    case "$outcome" in
      ok\ *)
        echo "# $region: host $instance holds M: ${outcome#ok }"
        return 0
        ;;
      refused\ *)
        echo "deploy: $stack: host $instance logged: ${outcome#refused }" >&2
        echo "deploy: stopped; nothing more is deployed" >&2
        exit 1
        ;;
    esac
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "deploy: $stack: host $instance logged no start outcome in /ghost-seal/$stack within ${start_wait}s; stopped, nothing more is deployed" >&2
      exit 1
    fi
    sleep "$start_poll"
  done
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
  # Nothing more is deployed until this host logged that it holds M.
  wait_for_m "$region"
}

# Regions whose existing host holds M while fewer than two other regions
# did: left as they are now, deployed in the second pass.
later=()

for index in $(seq 0 $((count - 1))); do
  region="${region_names[index]}"
  if stack_exists "$region" "$prefix-$region"; then
    # Its deploy may replace its host. A host that holds M is replaced only
    # once two other regions hold M too; one that may hold M (it logged no
    # outcome, or cannot be checked) only while another region holds M.
    if holds_m "$region"; then
      if ! two_others_hold_m "$region"; then
        echo "# $region: its host holds M and $why; $prefix-$region is left as it is until the second pass."
        later+=("$index")
        continue
      fi
    else
      echo "# $region: $why."
      other_holders "$region"
      if [ "$holders" -lt 1 ]; then
        echo "deploy: not replacing the host of $prefix-$region: no other region holds M and serves ($why), so it may hold the only M; stopped, nothing more is deployed" >&2
        exit 1
      fi
    fi
  fi
  deploy_region "$index"
done

# A region deployed before a later peer existed has no address for it: it
# serves no Fill or Open until it is deployed again with every address. Its
# host is replaced, so this runs only once every region holds M, one region
# at a time, each only once two other regions hold M and serve: never while
# it may be the only M holder.
again=()
for index in "${!region_names[@]}"; do
  for listed in ${missing[@]+"${missing[@]}"} ${later[@]+"${later[@]}"}; do
    if [ "$listed" = "$index" ]; then
      again+=("$index")
      break
    fi
  done
done
if [ "${#again[@]}" -gt 0 ]; then
  missing=()
  for region in "${region_names[@]}"; do
    if ! holds_m "$region"; then
      echo "deploy: the second pass needs every region to hold M, and $why; stopped, nothing more is deployed" >&2
      exit 1
    fi
  done
  echo "# again, now that every region exists and holds M: each with both anchor peers' addresses, one at a time."
  for index in "${again[@]}"; do
    region="${region_names[index]}"
    if ! two_others_hold_m "$region"; then
      echo "deploy: not replacing the host of $prefix-$region: $why; stopped, nothing more is deployed" >&2
      exit 1
    fi
    deploy_region "$index"
  done
elif [ "$apply" = 0 ]; then
  echo "# with --apply, a region deployed before a later peer existed is deployed again at the end with its address,"
  echo "# only once every region logged that it holds M: one region at a time, each only once two other regions hold M and serve."
fi
