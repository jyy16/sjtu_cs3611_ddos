#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash defense/iptables_rules.sh --target-port PORT --syn-rate RATE --http-rate RATE --project-tag TAG

Install baseline DDoS mitigation rules.

Options:
  --target-port PORT   Victim HTTP port to protect.
  --syn-rate RATE      Per-source SYN packet limit, packets per second.
  --http-rate RATE     Per-source HTTP/connection limit, requests or connections per second.
  --project-tag TAG    Comment/tag used to identify project-owned rules.
  -h, --help           Show this help.

Environment:
  DEFENSE_BACKEND      iptables or nftables. Default: iptables.
  IPTABLES             iptables binary name or path. Default: iptables.
  NFT                  nft binary name or path when DEFENSE_BACKEND=nftables.
  NFT_TABLE_NAME       nftables table name. Default: sanitized project tag.
  SUDO                 sudo binary name or path. Default: sudo.

Installed rules:
  1. Create project chains CS3611_DDOS and CS3611_DDOS_BL.
  2. Insert one INPUT jump to CS3611_DDOS if missing.
  3. Drop blacklisted sources through CS3611_DDOS_BL.
  4. Drop INVALID packets and abnormal TCP flag combinations.
  5. Drop per-source SYN traffic above --syn-rate.
  6. Drop per-source new HTTP connections above --http-rate.
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

TARGET_PORT=""
SYN_RATE=""
HTTP_RATE=""
PROJECT_TAG=""
DEFENSE_BACKEND="${DEFENSE_BACKEND:-iptables}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target-port)
      TARGET_PORT="${2:-}"
      shift 2
      ;;
    --syn-rate)
      SYN_RATE="${2:-}"
      shift 2
      ;;
    --http-rate)
      HTTP_RATE="${2:-}"
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

if [[ -z "$TARGET_PORT" || -z "$SYN_RATE" || -z "$HTTP_RATE" || -z "$PROJECT_TAG" ]]; then
  die "Missing required options."
fi

is_uint "$TARGET_PORT" || die "--target-port must be numeric: $TARGET_PORT"
is_uint "$SYN_RATE" || die "--syn-rate must be numeric: $SYN_RATE"
is_uint "$HTTP_RATE" || die "--http-rate must be numeric: $HTTP_RATE"
[[ "$TARGET_PORT" -ge 1 && "$TARGET_PORT" -le 65535 ]] || die "--target-port out of range: $TARGET_PORT"
[[ "$SYN_RATE" -ge 1 ]] || die "--syn-rate must be greater than 0"
[[ "$HTTP_RATE" -ge 1 ]] || die "--http-rate must be greater than 0"

BACKEND="$(normalize_backend "$DEFENSE_BACKEND")"
if [[ "$BACKEND" == "nftables" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  NFTABLES_CMD=(
    bash "$SCRIPT_DIR/nftables_rules.sh"
    --target-port "$TARGET_PORT"
    --syn-rate "$SYN_RATE"
    --http-rate "$HTTP_RATE"
    --project-tag "$PROJECT_TAG"
  )
  if [[ -n "${NFT_TABLE_NAME:-}" ]]; then
    NFTABLES_CMD+=(--table-name "$NFT_TABLE_NAME")
  fi
  exec "${NFTABLES_CMD[@]}"
fi

BASE_CHAIN="CS3611_DDOS"
BLACKLIST_CHAIN="CS3611_DDOS_BL"
IPTABLES_BIN="${IPTABLES:-iptables}"
SUDO_BIN="${SUDO:-sudo}"
SYN_HASHLIMIT_NAME="cs3611_ddos_syn"
HTTP_HASHLIMIT_NAME="cs3611_ddos_http"
LOOPBACK_SYN_HASHLIMIT_NAME="cs3611_lb_syn"
LOOPBACK_HTTP_HASHLIMIT_NAME="cs3611_lb_http"

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

append_unique "$BASE_CHAIN" \
  -m conntrack --ctstate INVALID \
  -m comment --comment "$PROJECT_TAG drop-invalid" \
  -j DROP

append_unique "$BASE_CHAIN" \
  -p tcp --tcp-flags ALL NONE \
  -m comment --comment "$PROJECT_TAG drop-null-flags" \
  -j DROP

append_unique "$BASE_CHAIN" \
  -p tcp --tcp-flags ALL ALL \
  -m comment --comment "$PROJECT_TAG drop-xmas-flags" \
  -j DROP

append_unique "$BASE_CHAIN" \
  -p tcp --tcp-flags SYN,FIN SYN,FIN \
  -m comment --comment "$PROJECT_TAG drop-syn-fin" \
  -j DROP

append_unique "$BASE_CHAIN" \
  -p tcp --tcp-flags SYN,RST SYN,RST \
  -m comment --comment "$PROJECT_TAG drop-syn-rst" \
  -j DROP

append_unique "$BASE_CHAIN" \
  -s 127.0.0.0/8 \
  -p tcp --dport "$TARGET_PORT" --syn \
  -m hashlimit \
  --hashlimit-name "$LOOPBACK_SYN_HASHLIMIT_NAME" \
  --hashlimit-mode dstip \
  --hashlimit-above "${SYN_RATE}/second" \
  --hashlimit-burst "$SYN_RATE" \
  -m comment --comment "$PROJECT_TAG loopback-syn-aggregate-limit" \
  -j DROP

append_unique "$BASE_CHAIN" \
  -p tcp --dport "$TARGET_PORT" --syn \
  -m hashlimit \
  --hashlimit-name "$SYN_HASHLIMIT_NAME" \
  --hashlimit-mode srcip \
  --hashlimit-above "${SYN_RATE}/second" \
  --hashlimit-burst "$SYN_RATE" \
  -m comment --comment "$PROJECT_TAG syn-rate-limit" \
  -j DROP

append_unique "$BASE_CHAIN" \
  -s 127.0.0.0/8 \
  -p tcp --dport "$TARGET_PORT" \
  -m conntrack --ctstate NEW \
  -m hashlimit \
  --hashlimit-name "$LOOPBACK_HTTP_HASHLIMIT_NAME" \
  --hashlimit-mode dstip \
  --hashlimit-above "${HTTP_RATE}/second" \
  --hashlimit-burst "$HTTP_RATE" \
  -m comment --comment "$PROJECT_TAG loopback-http-aggregate-limit" \
  -j DROP

append_unique "$BASE_CHAIN" \
  -p tcp --dport "$TARGET_PORT" \
  -m conntrack --ctstate NEW \
  -m hashlimit \
  --hashlimit-name "$HTTP_HASHLIMIT_NAME" \
  --hashlimit-mode srcip \
  --hashlimit-above "${HTTP_RATE}/second" \
  --hashlimit-burst "$HTTP_RATE" \
  -m comment --comment "$PROJECT_TAG http-new-connection-limit" \
  -j DROP

append_unique "$BASE_CHAIN" \
  -p udp --dport "$TARGET_PORT" \
  -m comment --comment "$PROJECT_TAG drop-udp-to-http-port" \
  -j DROP

printf '[defense] baseline iptables rules installed idempotently: chain=%s blacklist_chain=%s port=%s syn_rate=%s/s http_rate=%s/s tag=%s\n' \
  "$BASE_CHAIN" "$BLACKLIST_CHAIN" "$TARGET_PORT" "$SYN_RATE" "$HTTP_RATE" "$PROJECT_TAG"
