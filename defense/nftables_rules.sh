#!/usr/bin/env bash
set -Eeuo pipefail

TARGET_PORT="${TARGET_PORT:-8080}"
SYN_RATE="${SYN_RATE:-50}"
HTTP_RATE="${HTTP_RATE:-120}"
PROJECT_TAG="${PROJECT_TAG:-cs3611-ddos}"
TABLE_NAME="${NFT_TABLE_NAME:-}"
FAMILY="${NFT_FAMILY:-inet}"
NFT="${NFT:-nft}"
SUDO="${SUDO-sudo}"
DRY_RUN=0
COMMENT_TAG=""

usage() {
  cat <<'EOF'
Usage:
  bash defense/nftables_rules.sh [options]

Options:
  --target-port PORT       HTTP service port to protect. Default: 8080
  --syn-rate N             Max SYN packets per source per second. Default: 50
  --http-rate N            Max new HTTP connections per source per second. Default: 120
  --project-tag TAG        Rule/comment tag. Default: cs3611-ddos
  --table-name NAME        nftables table name. Default: sanitized project tag
  --dry-run                Print the generated nftables rules without applying them.
  -h, --help               Show this help.

The script creates one project-owned nftables table and replaces only that table
when re-run. It installs a shared cleaning chain for input and forward traffic:
  - per-source SYN flood limiting
  - per-source HTTP/new-connection limiting
  - abnormal TCP flag filtering
  - UDP traffic filtering for the protected HTTP port
  - a timeout-capable IPv4 blacklist set for optional block_ip integration
EOF
}

die() {
  printf '[nftables][error] %s\n' "$*" >&2
  exit 1
}

sanitize_identifier() {
  local ident
  ident="$(printf '%s' "$1" | sed 's/[^A-Za-z0-9_]/_/g')"
  [[ -n "$ident" ]] || ident="cs3611_ddos"
  [[ "$ident" =~ ^[A-Za-z_] ]] || ident="p_${ident}"
  printf '%s' "$ident"
}

sanitize_comment() {
  local ident
  ident="$(printf '%s' "$1" | sed 's/[^A-Za-z0-9_.:-]/_/g')"
  [[ -n "$ident" ]] || ident="cs3611-ddos"
  printf '%s' "$ident"
}

is_uint() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

validate_args() {
  is_uint "$TARGET_PORT" || die "--target-port must be numeric: $TARGET_PORT"
  [[ "$TARGET_PORT" -ge 1 && "$TARGET_PORT" -le 65535 ]] || die "--target-port out of range: $TARGET_PORT"
  is_uint "$SYN_RATE" || die "--syn-rate must be numeric: $SYN_RATE"
  [[ "$SYN_RATE" -gt 0 ]] || die "--syn-rate must be greater than 0"
  is_uint "$HTTP_RATE" || die "--http-rate must be numeric: $HTTP_RATE"
  [[ "$HTTP_RATE" -gt 0 ]] || die "--http-rate must be greater than 0"
  [[ "$FAMILY" =~ ^[A-Za-z0-9_]+$ ]] || die "Invalid nftables family: $FAMILY"

  if [[ -z "$TABLE_NAME" ]]; then
    TABLE_NAME="$(sanitize_identifier "$PROJECT_TAG")"
  fi
  [[ "$TABLE_NAME" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "Invalid nftables table name: $TABLE_NAME"
  COMMENT_TAG="$(sanitize_comment "$PROJECT_TAG")"
}

need_tools() {
  if ! command -v "$NFT" >/dev/null 2>&1; then
    die "nft command not found. Install nftables or set NFT=/path/to/nft."
  fi
  if [[ -n "$SUDO" && "$(id -u)" != "0" ]] && ! command -v "$SUDO" >/dev/null 2>&1; then
    die "sudo command not found. Run as root or set SUDO=''."
  fi
}

run_nft() {
  if [[ -n "$SUDO" && "$(id -u)" != "0" ]]; then
    "$SUDO" "$NFT" "$@"
  else
    "$NFT" "$@"
  fi
}

print_nft_stdin_cmd() {
  if [[ -n "$SUDO" && "$(id -u)" != "0" ]]; then
    printf '+ %q %q -f -\n' "$SUDO" "$NFT"
  else
    printf '+ %q -f -\n' "$NFT"
  fi
}

emit_rules() {
  local syn_burst http_burst
  syn_burst=$((SYN_RATE * 2))
  http_burst=$((HTTP_RATE * 2))

  cat <<EOF
table $FAMILY $TABLE_NAME {
  set blacklist_v4 {
    type ipv4_addr
    flags timeout
  }

  chain ddos_common {
    ip saddr @blacklist_v4 counter drop comment "$COMMENT_TAG blacklist"

    ct state invalid counter drop comment "$COMMENT_TAG drop-invalid"
    tcp flags & (fin|syn|rst|psh|ack|urg) == 0 counter drop comment "$COMMENT_TAG drop-null-flags"
    tcp flags & (fin|syn) == (fin|syn) counter drop comment "$COMMENT_TAG drop-syn-fin"
    tcp flags & (syn|rst) == (syn|rst) counter drop comment "$COMMENT_TAG drop-syn-rst"
    tcp flags & (fin|psh|urg) == (fin|psh|urg) counter drop comment "$COMMENT_TAG drop-xmas-flags"

    tcp dport $TARGET_PORT tcp flags & (fin|syn|rst|ack) == syn meter syn_per_src { ip saddr limit rate over $SYN_RATE/second burst $syn_burst packets } counter drop comment "$COMMENT_TAG syn-rate-limit"

    tcp dport $TARGET_PORT ct state new meter http_conn_per_src { ip saddr limit rate over $HTTP_RATE/second burst $http_burst packets } counter drop comment "$COMMENT_TAG http-new-connection-limit"

    udp dport $TARGET_PORT counter drop comment "$COMMENT_TAG drop-udp-to-http-port"
  }

  chain input {
    type filter hook input priority -10; policy accept;
    jump ddos_common
  }

  chain forward {
    type filter hook forward priority -10; policy accept;
    jump ddos_common
  }
}
EOF
}

apply_rules() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '# Project-owned nftables table: %s %s\n' "$FAMILY" "$TABLE_NAME"
    printf '# Re-run behavior: delete this table if it exists, then recreate it.\n'
    emit_rules
    return 0
  fi

  if run_nft list table "$FAMILY" "$TABLE_NAME" >/dev/null 2>&1; then
    run_nft delete table "$FAMILY" "$TABLE_NAME"
  fi

  print_nft_stdin_cmd
  if [[ -n "$SUDO" && "$(id -u)" != "0" ]]; then
    emit_rules | "$SUDO" "$NFT" -f -
  else
    emit_rules | "$NFT" -f -
  fi

  printf '[nftables] Applied table %s %s for target port %s (syn=%s/s, http=%s/s, tag=%s)\n' \
    "$FAMILY" "$TABLE_NAME" "$TARGET_PORT" "$SYN_RATE" "$HTTP_RATE" "$PROJECT_TAG"
}

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
    --table-name)
      TABLE_NAME="${2:-}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown option: $1"
      ;;
  esac
done

validate_args
if [[ "$DRY_RUN" != "1" ]]; then
  need_tools
fi
apply_rules
