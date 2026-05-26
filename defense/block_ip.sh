#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash defense/block_ip.sh --ip IP --reason REASON --ttl SECONDS --project-tag TAG

Block or rate-limit one suspicious source IP.

Options:
  --ip IP              Source IP to block or rate-limit.
  --reason REASON      Human-readable reason, recorded in logs/rules.
  --ttl SECONDS        Suggested block duration in seconds.
  --project-tag TAG    Comment/tag used to identify project-owned rules.
  -h, --help           Show this help.

Safety rules:
  Do not DROP 127.0.0.1 in local demos.
  Do not block victim or gateway IPs.

Environment:
  DEFENSE_BACKEND      iptables or nftables. Default: iptables.
  IPTABLES             iptables binary name or path. Default: iptables.
  NFT                  nft binary name or path when DEFENSE_BACKEND=nftables.
  NFT_FAMILY           nftables family when DEFENSE_BACKEND=nftables. Default: inet.
  NFT_TABLE_NAME       nftables table name. Default: sanitized project tag.
  SUDO                 sudo binary name or path. Default: sudo.
  TARGET_IP            Victim IP. Used to avoid blocking the victim.
  VICTIM_IP            Victim IP alias. Takes the same role as TARGET_IP.
  GATEWAY_IP           Gateway IP. Used to avoid blocking the gateway.
  PROTECTED_IPS        Extra comma/space-separated IPs that must not be blocked.
  LOOPBACK_RATE        Rate limit for 127.0.0.0/8 instead of DROP. Default: 20.
  DEFENSE_LOG_DIR      Directory for block action logs. Default: data/logs.
EOF
}

die() {
  printf '[defense][error] %s\n' "$*" >&2
  exit 1
}

is_uint() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

normalize_backend() {
  local backend
  backend="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$backend" in
    iptables)
      printf 'iptables\n'
      ;;
    nft|nftables)
      printf 'nftables\n'
      ;;
    *)
      die "DEFENSE_BACKEND must be iptables or nftables: $1"
      ;;
  esac
}

sanitize_identifier() {
  local ident
  ident="$(printf '%s' "$1" | sed 's/[^A-Za-z0-9_]/_/g')"
  [[ -n "$ident" ]] || ident="cs3611_ddos"
  [[ "$ident" =~ ^[A-Za-z_] ]] || ident="p_${ident}"
  printf '%s' "$ident"
}

nft_quote() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

is_ipv4() {
  local ip="$1"
  local a b c d value

  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -r a b c d <<<"$ip"
  for octet in "$a" "$b" "$c" "$d"; do
    is_uint "$octet" || return 1
    value=$((10#$octet))
    [[ "$value" -ge 0 && "$value" -le 255 ]] || return 1
  done
}

first_octet() {
  local ip="$1"
  printf '%d\n' "$((10#${ip%%.*}))"
}

second_octet() {
  local rest="${1#*.}"
  printf '%d\n' "$((10#${rest%%.*}))"
}

is_loopback_ipv4() {
  [[ "$(first_octet "$1")" -eq 127 ]]
}

is_private_or_loopback_ipv4() {
  local ip="$1"
  local a b

  a="$(first_octet "$ip")"
  b="$(second_octet "$ip")"

  [[ "$a" -eq 127 ]] && return 0
  [[ "$a" -eq 10 ]] && return 0
  [[ "$a" -eq 192 && "$b" -eq 168 ]] && return 0
  [[ "$a" -eq 172 && "$b" -ge 16 && "$b" -le 31 ]] && return 0
  return 1
}

detect_default_gateway() {
  local output line token next

  command -v ip >/dev/null 2>&1 || return 0
  output="$(ip route show default 2>/dev/null || true)"
  line="${output%%$'\n'*}"

  set -- $line
  while [[ $# -gt 0 ]]; do
    token="$1"
    next="${2:-}"
    if [[ "$token" == "via" && -n "$next" ]]; then
      printf '%s\n' "$next"
      return 0
    fi
    shift
  done
}

is_protected_ip() {
  local ip="$1"
  local detected_gateway protected protected_list

  for protected in "${VICTIM_IP:-}" "${TARGET_IP:-}" "${GATEWAY_IP:-}"; do
    [[ -n "$protected" && "$ip" == "$protected" ]] && return 0
  done

  detected_gateway="$(detect_default_gateway)"
  [[ -n "$detected_gateway" && "$ip" == "$detected_gateway" ]] && return 0

  protected_list="${PROTECTED_IPS:-}"
  for protected in ${protected_list//,/ }; do
    [[ -n "$protected" && "$ip" == "$protected" ]] && return 0
  done

  return 1
}

IP=""
REASON=""
TTL=""
PROJECT_TAG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ip)
      IP="${2:-}"
      shift 2
      ;;
    --reason)
      REASON="${2:-}"
      shift 2
      ;;
    --ttl)
      TTL="${2:-}"
      shift 2
      ;;
    --project-tag)
      PROJECT_TAG="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf '[defense][error] Unknown option: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$IP" || -z "$REASON" || -z "$TTL" || -z "$PROJECT_TAG" ]]; then
  die "Missing required options."
fi

is_ipv4 "$IP" || die "--ip must be a valid IPv4 address: $IP"
is_uint "$TTL" || die "--ttl must be numeric: $TTL"
[[ "$TTL" -ge 1 ]] || die "--ttl must be greater than 0"
is_private_or_loopback_ipv4 "$IP" || die "Refusing to block public IP: $IP"

BASE_CHAIN="CS3611_DDOS"
BLACKLIST_CHAIN="CS3611_DDOS_BL"
DEFENSE_BACKEND="${DEFENSE_BACKEND:-iptables}"
IPTABLES_BIN="${IPTABLES:-iptables}"
NFT_BIN="${NFT:-nft}"
NFT_FAMILY="${NFT_FAMILY:-inet}"
SUDO_BIN="${SUDO:-sudo}"
LOOPBACK_RATE="${LOOPBACK_RATE:-20}"
DEFENSE_LOG_DIR="${DEFENSE_LOG_DIR:-data/logs}"

is_uint "$LOOPBACK_RATE" || die "LOOPBACK_RATE must be numeric: $LOOPBACK_RATE"
[[ "$LOOPBACK_RATE" -ge 1 ]] || die "LOOPBACK_RATE must be greater than 0"

record_action() {
  local action="$1"
  local ts

  ts="$(date -Iseconds 2>/dev/null || date)"
  if mkdir -p "$DEFENSE_LOG_DIR" 2>/dev/null; then
    printf '%s,action=%s,ip=%s,reason=%s,ttl=%s,tag=%s\n' \
      "$ts" "$action" "$IP" "$REASON" "$TTL" "$PROJECT_TAG" \
      >>"$DEFENSE_LOG_DIR/defense_blocks.log" 2>/dev/null || true
  fi
}

BACKEND="$(normalize_backend "$DEFENSE_BACKEND")"

if [[ "$BACKEND" == "nftables" ]]; then
  [[ "$NFT_FAMILY" =~ ^[A-Za-z0-9_]+$ ]] || die "Invalid nftables family: $NFT_FAMILY"
  NFT_TABLE="${NFT_TABLE_NAME:-$(sanitize_identifier "$PROJECT_TAG")}"
  [[ "$NFT_TABLE" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "Invalid nftables table name: $NFT_TABLE"

  command -v "$NFT_BIN" >/dev/null 2>&1 || die "nft command not found: $NFT_BIN"
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    NFT_CMD=("$NFT_BIN")
  else
    command -v "$SUDO_BIN" >/dev/null 2>&1 || die "not root and sudo command not found"
    NFT_CMD=("$SUDO_BIN" "$NFT_BIN")
  fi

  nft_run() {
    "${NFT_CMD[@]}" "$@"
  }

  nft_table_exists() {
    nft_run list table "$NFT_FAMILY" "$NFT_TABLE" >/dev/null 2>&1
  }

  nft_rule_comment_exists() {
    local comment="$1"
    nft_run -a list chain "$NFT_FAMILY" "$NFT_TABLE" ddos_common 2>/dev/null \
      | grep -F "comment \"$comment\"" >/dev/null 2>&1
  }

  ensure_nft_baseline() {
    local script_dir cmd

    if ! nft_table_exists; then
      script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
      cmd=(
        bash "$script_dir/nftables_rules.sh"
        --target-port "${TARGET_PORT:-8080}"
        --syn-rate "${SYN_LIMIT:-50}"
        --http-rate "${HTTP_LIMIT:-120}"
        --project-tag "$PROJECT_TAG"
      )
      if [[ -n "${NFT_TABLE_NAME:-}" ]]; then
        cmd+=(--table-name "$NFT_TABLE")
      fi
      "${cmd[@]}"
    fi

    nft_run list set "$NFT_FAMILY" "$NFT_TABLE" blacklist_v4 >/dev/null 2>&1 \
      || die "nftables blacklist set is missing; rerun defense/iptables_rules.sh with DEFENSE_BACKEND=nftables"
  }

  add_nft_loopback_limit() {
    local comment escaped_comment

    comment="$PROJECT_TAG loopback-rate-limit $IP"
    if nft_rule_comment_exists "$comment"; then
      return 0
    fi

    escaped_comment="$(nft_quote "$comment")"
    printf 'add rule %s %s ddos_common ip saddr %s tcp flags & (fin|syn|rst|ack) == syn limit rate over %s/second burst %s packets counter drop comment "%s"\n' \
      "$NFT_FAMILY" "$NFT_TABLE" "$IP" "$LOOPBACK_RATE" "$LOOPBACK_RATE" "$escaped_comment" \
      | nft_run -f -
  }

  ensure_nft_baseline

  if is_loopback_ipv4 "$IP"; then
    add_nft_loopback_limit
    record_action "rate_limit_loopback_nftables"
    printf '[defense] nftables loopback source rate-limited instead of dropped: ip=%s rate=%s/s reason=%s ttl=%s tag=%s table=%s\n' \
      "$IP" "$LOOPBACK_RATE" "$REASON" "$TTL" "$PROJECT_TAG" "$NFT_TABLE"
    exit 0
  fi

  if is_protected_ip "$IP"; then
    die "Refusing to block protected IP: $IP"
  fi

  nft_run delete element "$NFT_FAMILY" "$NFT_TABLE" blacklist_v4 "{ $IP }" >/dev/null 2>&1 || true
  nft_run add element "$NFT_FAMILY" "$NFT_TABLE" blacklist_v4 "{ $IP timeout ${TTL}s }"

  record_action "drop_private_ip_nftables"
  printf '[defense] nftables private source blocked: ip=%s reason=%s ttl=%s tag=%s table=%s\n' \
    "$IP" "$REASON" "$TTL" "$PROJECT_TAG" "$NFT_TABLE"
  exit 0
fi

command -v "$IPTABLES_BIN" >/dev/null 2>&1 || die "iptables command not found: $IPTABLES_BIN"

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  IPTABLES_CMD=("$IPTABLES_BIN" -w)
else
  command -v "$SUDO_BIN" >/dev/null 2>&1 || die "not root and sudo command not found"
  IPTABLES_CMD=("$SUDO_BIN" "$IPTABLES_BIN" -w)
fi

iptables_run() {
  "${IPTABLES_CMD[@]}" "$@"
}

chain_exists() {
  iptables_run -L "$1" -n >/dev/null 2>&1
}

ensure_chain() {
  local chain="$1"

  if ! chain_exists "$chain"; then
    iptables_run -N "$chain"
  fi
}

append_unique() {
  local chain="$1"
  shift

  if ! iptables_run -C "$chain" "$@" >/dev/null 2>&1; then
    iptables_run -A "$chain" "$@"
  fi
}

insert_unique() {
  local chain="$1"
  shift

  if ! iptables_run -C "$chain" "$@" >/dev/null 2>&1; then
    iptables_run -I "$chain" 1 "$@"
  fi
}

ensure_chain "$BASE_CHAIN"
ensure_chain "$BLACKLIST_CHAIN"

insert_unique INPUT \
  -m comment --comment "$PROJECT_TAG jump-to-defense" \
  -j "$BASE_CHAIN"

append_unique "$BASE_CHAIN" \
  -m comment --comment "$PROJECT_TAG jump-to-blacklist" \
  -j "$BLACKLIST_CHAIN"

if is_loopback_ipv4 "$IP"; then
  HASH_IP="${IP//./_}"
  append_unique "$BASE_CHAIN" \
    -s "$IP" \
    -p tcp \
    -m conntrack --ctstate NEW \
    -m hashlimit \
    --hashlimit-name "cs3611_local_${HASH_IP}" \
    --hashlimit-mode srcip \
    --hashlimit-above "${LOOPBACK_RATE}/second" \
    --hashlimit-burst "$LOOPBACK_RATE" \
    -m comment --comment "$PROJECT_TAG loopback-rate-limit $IP" \
    -j DROP

  record_action "rate_limit_loopback"
  printf '[defense] loopback source rate-limited instead of dropped: ip=%s rate=%s/s reason=%s ttl=%s tag=%s\n' \
    "$IP" "$LOOPBACK_RATE" "$REASON" "$TTL" "$PROJECT_TAG"
  exit 0
fi

if is_protected_ip "$IP"; then
  die "Refusing to block protected IP: $IP"
fi

append_unique "$BLACKLIST_CHAIN" \
  -s "$IP" \
  -m comment --comment "$PROJECT_TAG blacklist $IP" \
  -j DROP

record_action "drop_private_ip"
printf '[defense] private source blocked: ip=%s reason=%s ttl=%s tag=%s\n' \
  "$IP" "$REASON" "$TTL" "$PROJECT_TAG"
