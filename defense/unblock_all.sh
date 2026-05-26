#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash defense/unblock_all.sh --project-tag TAG

Remove only firewall rules created by this project.

Options:
  --project-tag TAG    Comment/tag used to identify project-owned rules.
  -h, --help           Show this help.

Environment:
  DEFENSE_BACKEND      iptables or nftables. Default: iptables.
  IPTABLES             iptables binary name or path. Default: iptables.
  NFT                  nft binary name or path when DEFENSE_BACKEND=nftables.
  NFT_FAMILY           nftables family when DEFENSE_BACKEND=nftables. Default: inet.
  NFT_TABLE_NAME       nftables table name. Default: sanitized project tag.
  SUDO                 sudo binary name or path. Default: sudo.

Cleanup scope:
  1. Delete INPUT jumps tagged as "TAG jump-to-defense".
  2. Flush and delete CS3611_DDOS if it exists.
  3. Flush and delete CS3611_DDOS_BL if it exists.
  No built-in iptables chains are flushed.
EOF
}

die() {
  printf '[defense][error] %s\n' "$*" >&2
  exit 1
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

PROJECT_TAG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
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

if [[ -z "$PROJECT_TAG" ]]; then
  die "Missing required option: --project-tag"
fi

BASE_CHAIN="CS3611_DDOS"
BLACKLIST_CHAIN="CS3611_DDOS_BL"
DEFENSE_BACKEND="${DEFENSE_BACKEND:-iptables}"
IPTABLES_BIN="${IPTABLES:-iptables}"
NFT_BIN="${NFT:-nft}"
NFT_FAMILY="${NFT_FAMILY:-inet}"
SUDO_BIN="${SUDO:-sudo}"

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

  if nft_run list table "$NFT_FAMILY" "$NFT_TABLE" >/dev/null 2>&1; then
    nft_run delete table "$NFT_FAMILY" "$NFT_TABLE"
  fi

  printf '[defense] project nftables rules removed idempotently: family=%s table=%s tag=%s\n' \
    "$NFT_FAMILY" "$NFT_TABLE" "$PROJECT_TAG"
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

delete_jump_if_present() {
  local chain="$1"
  shift

  while iptables_run -C "$chain" "$@" >/dev/null 2>&1; do
    iptables_run -D "$chain" "$@"
  done
}

flush_chain_if_present() {
  local chain="$1"

  if chain_exists "$chain"; then
    iptables_run -F "$chain"
  fi
}

delete_chain_if_present() {
  local chain="$1"

  if chain_exists "$chain"; then
    if ! iptables_run -X "$chain" >/dev/null 2>&1; then
      printf '[defense][warn] Chain %s still has external references; left it empty but did not delete it.\n' "$chain" >&2
    fi
  fi
}

delete_jump_if_present INPUT \
  -m comment --comment "$PROJECT_TAG jump-to-defense" \
  -j "$BASE_CHAIN"

flush_chain_if_present "$BASE_CHAIN"
flush_chain_if_present "$BLACKLIST_CHAIN"

delete_chain_if_present "$BASE_CHAIN"
delete_chain_if_present "$BLACKLIST_CHAIN"

printf '[defense] project firewall rules removed idempotently: chain=%s blacklist_chain=%s tag=%s\n' \
  "$BASE_CHAIN" "$BLACKLIST_CHAIN" "$PROJECT_TAG"
