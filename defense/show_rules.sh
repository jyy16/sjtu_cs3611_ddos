#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash defense/show_rules.sh --project-tag TAG

Show project-owned defense rules.

Options:
  --project-tag TAG    Comment/tag used to identify project-owned rules.
  -h, --help           Show this help.

Output sections:
  Current blacklist IPs
  Current rate-limit rules
  Current traffic-cleaning rules
  Raw rule counters for project chains

Environment:
  DEFENSE_BACKEND      iptables or nftables. Default: iptables.
  IPTABLES             iptables binary name or path. Default: iptables.
  NFT                  nft binary name or path when DEFENSE_BACKEND=nftables.
  NFT_FAMILY           nftables family when DEFENSE_BACKEND=nftables. Default: inet.
  NFT_TABLE_NAME       nftables table name. Default: sanitized project tag.
  SUDO                 sudo binary name or path. Default: sudo.
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

section() {
  printf '\n========== %s ==========\n' "$1"
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

  print_nft_set() {
    if ! nft_run list set "$NFT_FAMILY" "$NFT_TABLE" blacklist_v4 2>/dev/null; then
      printf '  <nftables set %s %s blacklist_v4 not installed>\n' "$NFT_FAMILY" "$NFT_TABLE"
    fi
  }

  print_nft_matching_rules() {
    local output matched line pattern

    if ! output="$(nft_run -a list chain "$NFT_FAMILY" "$NFT_TABLE" ddos_common 2>/dev/null)"; then
      printf '  <nftables chain %s %s ddos_common not installed>\n' "$NFT_FAMILY" "$NFT_TABLE"
      return
    fi

    matched=0
    while IFS= read -r line; do
      [[ "$line" == *"$PROJECT_TAG"* ]] || continue
      for pattern in "$@"; do
        if [[ "$line" == *"$pattern"* ]]; then
          printf '  %s\n' "$line"
          matched=1
          break
        fi
      done
    done <<<"$output"

    if [[ "$matched" -eq 0 ]]; then
      printf '  <none>\n'
    fi
  }

  section "Current Blacklist IPs"
  printf 'Backend: nftables\n'
  printf 'Project tag: %s\n' "$PROJECT_TAG"
  print_nft_set

  section "Current Rate-Limit Rules"
  printf 'Backend: nftables\n'
  printf 'Project tag: %s\n' "$PROJECT_TAG"
  print_nft_matching_rules \
    "syn-rate-limit" \
    "http-new-connection-limit" \
    "loopback-rate-limit"

  section "Current Traffic-Cleaning Rules"
  printf 'Backend: nftables\n'
  printf 'Project tag: %s\n' "$PROJECT_TAG"
  print_nft_matching_rules \
    "drop-invalid" \
    "drop-null-flags" \
    "drop-xmas-flags" \
    "drop-syn-fin" \
    "drop-syn-rst" \
    "drop-udp-to-http-port"

  section "Raw Counters: nftables $NFT_FAMILY $NFT_TABLE"
  if ! nft_run -a list table "$NFT_FAMILY" "$NFT_TABLE"; then
    printf '  <nftables table %s %s not installed>\n' "$NFT_FAMILY" "$NFT_TABLE"
  fi
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

chain_table() {
  local chain="$1"

  if ! chain_exists "$chain"; then
    return 1
  fi

  iptables_run -L "$chain" -n -v -x --line-numbers
}

print_matching_rules() {
  local chain="$1"
  shift
  local output matched line pattern

  if ! output="$(chain_table "$chain" 2>/dev/null)"; then
    printf '  <%s not installed>\n' "$chain"
    return
  fi

  matched=0
  while IFS= read -r line; do
    [[ "$line" == *"$PROJECT_TAG"* ]] || continue
    for pattern in "$@"; do
      if [[ "$line" == *"$pattern"* ]]; then
        printf '  %s\n' "$line"
        matched=1
        break
      fi
    done
  done <<<"$output"

  if [[ "$matched" -eq 0 ]]; then
    printf '  <none>\n'
  fi
}

print_project_chain() {
  local chain="$1"

  if ! chain_table "$chain"; then
    printf '  <%s not installed>\n' "$chain"
  fi
}

section "Current Blacklist IPs"
printf 'Project tag: %s\n' "$PROJECT_TAG"
printf 'Columns include packet and byte counters before each rule.\n'
print_matching_rules "$BLACKLIST_CHAIN" "blacklist"

section "Current Rate-Limit Rules"
printf 'Project tag: %s\n' "$PROJECT_TAG"
printf 'Counters show how many packets were dropped by each limit rule.\n'
print_matching_rules "$BASE_CHAIN" \
  "syn-rate-limit" \
  "http-new-connection-limit" \
  "loopback-rate-limit"

section "Current Traffic-Cleaning Rules"
printf 'Project tag: %s\n' "$PROJECT_TAG"
printf 'Counters show abnormal traffic filtered by each cleanup rule.\n'
print_matching_rules "$BASE_CHAIN" \
  "drop-invalid" \
  "drop-null-flags" \
  "drop-xmas-flags" \
  "drop-syn-fin" \
  "drop-syn-rst"

section "Project Entrypoint"
print_matching_rules INPUT "jump-to-defense"

section "Raw Counters: $BASE_CHAIN"
print_project_chain "$BASE_CHAIN"

section "Raw Counters: $BLACKLIST_CHAIN"
print_project_chain "$BLACKLIST_CHAIN"
