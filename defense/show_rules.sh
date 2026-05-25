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
  IPTABLES             iptables binary name or path. Default: iptables.
  SUDO                 sudo binary name or path. Default: sudo.
EOF
}

die() {
  printf '[defense][error] %s\n' "$*" >&2
  exit 1
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
IPTABLES_BIN="${IPTABLES:-iptables}"
SUDO_BIN="${SUDO:-sudo}"

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

section() {
  printf '\n========== %s ==========\n' "$1"
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
