#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="${ENV_FILE:-scripts/demo.env}"
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

PYTHON="${PYTHON:-python3}"
SUDO="${SUDO:-sudo}"

TARGET_IP="${TARGET_IP:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-8080}"
TARGET_URL="${TARGET_URL:-http://${TARGET_IP}:${TARGET_PORT}/}"
CAPTURE_IFACE="${CAPTURE_IFACE:-lo}"

RUN_ID="${RUN_ID:-$(date +%Y%m%d_%H%M%S)}"
PROJECT_TAG="${PROJECT_TAG:-cs3611-ddos}"

NORMAL_SECONDS="${NORMAL_SECONDS:-10}"
ATTACK_SECONDS="${ATTACK_SECONDS:-20}"
NORMAL_RATE="${NORMAL_RATE:-5}"
SYN_RATE="${SYN_RATE:-200}"
HTTP_RATE="${HTTP_RATE:-80}"
UDP_RATE="${UDP_RATE:-100}"
SYN_LIMIT="${SYN_LIMIT:-50}"
HTTP_LIMIT="${HTTP_LIMIT:-120}"
FEATURE_WINDOW="${FEATURE_WINDOW:-1}"
CONFIDENCE_THRESHOLD="${CONFIDENCE_THRESHOLD:-0.80}"

MODEL_PATH="${MODEL_PATH:-models/saved/model.pth}"
TRAIN_FEATURES="${TRAIN_FEATURES:-data/features/train.csv}"
START_TARGET="${START_TARGET:-1}"
TARGET_SITE_DIR="${TARGET_SITE_DIR:-demo_site}"
TRAIN="${TRAIN:-0}"
DRY_RUN="${DRY_RUN:-0}"
CHECK_ONLY=0
STORAGE_BACKEND="${STORAGE_BACKEND:-none}"
REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}"
STORAGE_KEY_PREFIX="${STORAGE_KEY_PREFIX:-cs3611:ddos}"
STORAGE_FAIL_OPEN="${STORAGE_FAIL_OPEN:-0}"

PCAP_DIR="${PCAP_DIR:-data/pcap/${RUN_ID}}"
FEATURE_DIR="${FEATURE_DIR:-data/features/${RUN_ID}}"
LOG_DIR="${LOG_DIR:-data/logs/${RUN_ID}}"

export RUN_ID STORAGE_BACKEND REDIS_URL STORAGE_KEY_PREFIX STORAGE_FAIL_OPEN

TCPDUMP_PID=""
TARGET_PID=""

usage() {
  cat <<'EOF'
Usage:
  bash scripts/run_demo.sh [options]

Options:
  --dry-run                 Print commands without executing them.
  --check-only              Check required files and commands, then exit.
  --train                   Run model training before the live demo.
  --target-ip IP            Victim IP. Must be loopback or private IPv4.
  --target-port PORT        Victim HTTP port.
  --target-url URL          Victim HTTP URL.
  --iface IFACE             tcpdump capture interface, for example lo or h1-eth0.
  --run-id ID               Output folder suffix.
  -h, --help                Show this help.

Typical local demo:
  cp scripts/demo.env.example scripts/demo.env
  bash scripts/run_demo.sh --check-only
  bash scripts/run_demo.sh

Typical Mininet demo:
  START_TARGET=0 TARGET_IP=10.0.0.2 CAPTURE_IFACE=h1-eth0 bash scripts/run_demo.sh
EOF
}

log() {
  printf '[demo] %s\n' "$*"
}

phase() {
  printf '\n========== %s ==========\n' "$*"
}

die() {
  printf '[demo][error] %s\n' "$*" >&2
  exit 1
}

quote_cmd() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
}

run_cmd() {
  quote_cmd "$@"
  if [[ "$DRY_RUN" != "1" ]]; then
    "$@"
  fi
}

is_private_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^127\. ]] && return 0
  [[ "$ip" =~ ^10\. ]] && return 0
  [[ "$ip" =~ ^192\.168\. ]] && return 0
  [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 0
  return 1
}

storage_is_enabled() {
  case "$(printf '%s' "$STORAGE_BACKEND" | tr '[:upper:]' '[:lower:]')" in
    ""|none|off|false|0|file|files|disabled)
      return 1
      ;;
    *)
      return 0
      ;;
  esac
}

storage_fail_open_enabled() {
  case "$(printf '%s' "$STORAGE_FAIL_OPEN" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

validate_safety() {
  [[ "$TARGET_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "TARGET_IP must be an IPv4 address: $TARGET_IP"
  is_private_ipv4 "$TARGET_IP" || die "Refusing to run against public TARGET_IP=$TARGET_IP"
  [[ "$TARGET_PORT" =~ ^[0-9]+$ ]] || die "TARGET_PORT must be numeric: $TARGET_PORT"
  [[ "$TARGET_PORT" -ge 1 && "$TARGET_PORT" -le 65535 ]] || die "TARGET_PORT out of range: $TARGET_PORT"
}

need_file() {
  local path="$1"
  [[ -f "$path" ]] || MISSING_FILES+=("$path")
}

need_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || MISSING_CMDS+=("$cmd")
}

preflight() {
  phase "Preflight"
  MISSING_FILES=()
  MISSING_CMDS=()

  need_cmd "$PYTHON"
  need_cmd bash
  need_cmd curl
  need_cmd tcpdump
  if [[ -n "$SUDO" ]]; then
    need_cmd "$SUDO"
  fi

  need_file attacks/normal_traffic.py
  need_file attacks/syn_flood.py
  need_file attacks/http_flood.py
  need_file attacks/udp_reflection_sim.py
  need_file attacks/run_mixed_attack.sh
  need_file defense/unblock_all.sh
  need_file defense/iptables_rules.sh
  need_file defense/show_rules.sh
  need_file defense/block_ip.sh
  need_file defense/apply_decision.py
  need_file features/extract_features.py
  need_file features/feature_schema.md
  need_file models/train_mlp.py
  need_file models/infer.py
  need_file scripts/persist_demo_summary.py

  if [[ "$TRAIN" == "1" ]]; then
    need_file "$TRAIN_FEATURES"
  else
    need_file "$MODEL_PATH"
  fi

  if storage_is_enabled; then
    if [[ "$(printf '%s' "$STORAGE_BACKEND" | tr '[:upper:]' '[:lower:]')" != "redis" ]]; then
      MISSING_CMDS+=("supported storage backend: redis")
    elif ! "$PYTHON" - <<'PY'
from storage.redis_store import StorageError, _redis_client

try:
    _redis_client()
except StorageError as exc:
    raise SystemExit(f"[storage][error] {exc}")
PY
    then
      if storage_fail_open_enabled; then
        log "Redis storage check failed, continuing because STORAGE_FAIL_OPEN=1"
      else
        MISSING_CMDS+=("redis storage at ${REDIS_URL}")
      fi
    fi
  fi

  if [[ ${#MISSING_CMDS[@]} -gt 0 ]]; then
    printf 'Missing commands:\n' >&2
    printf '  %s\n' "${MISSING_CMDS[@]}" >&2
  fi
  if [[ ${#MISSING_FILES[@]} -gt 0 ]]; then
    printf 'Missing project files:\n' >&2
    printf '  %s\n' "${MISSING_FILES[@]}" >&2
  fi
  [[ ${#MISSING_CMDS[@]} -eq 0 && ${#MISSING_FILES[@]} -eq 0 ]] || die "Preflight failed. See docs/group_command_requirements.md."

  log "Preflight passed."
}

ensure_dirs() {
  mkdir -p "$PCAP_DIR" "$FEATURE_DIR" "$LOG_DIR" models/saved
}

start_target_server() {
  if [[ "$START_TARGET" != "1" ]]; then
    log "START_TARGET=0, assuming victim service is already running at $TARGET_URL"
    return
  fi

  phase "Start Victim HTTP Service"
  if [[ "$DRY_RUN" == "1" ]]; then
    quote_cmd "$PYTHON" -m http.server "$TARGET_PORT" --bind "$TARGET_IP" --directory "$TARGET_SITE_DIR"
    return
  fi

  if curl -fsS --max-time 2 "$TARGET_URL" >/dev/null 2>&1; then
    log "Target URL is already reachable; reusing existing service at $TARGET_URL"
    return
  fi

  quote_cmd "$PYTHON" -m http.server "$TARGET_PORT" --bind "$TARGET_IP" --directory "$TARGET_SITE_DIR"

  "$PYTHON" -m http.server "$TARGET_PORT" --bind "$TARGET_IP" --directory "$TARGET_SITE_DIR" \
    >"$LOG_DIR/target_server.log" 2>&1 &
  TARGET_PID="$!"
  sleep 1
  if ! kill -0 "$TARGET_PID" >/dev/null 2>&1; then
    die "Failed to start victim HTTP service on ${TARGET_IP}:${TARGET_PORT}; see $LOG_DIR/target_server.log"
  fi
}

check_target_url() {
  phase "Check Target Availability"
  quote_cmd curl -fsS --max-time 5 "$TARGET_URL"
  if [[ "$DRY_RUN" != "1" ]]; then
    curl -fsS --max-time 5 "$TARGET_URL" >/dev/null || die "Target URL is not reachable: $TARGET_URL"
  fi
}

start_capture() {
  local pcap="$1"
  phase "Start Capture: $pcap"
  if [[ -n "$SUDO" ]]; then
    quote_cmd "$SUDO" tcpdump -i "$CAPTURE_IFACE" -nn -w "$pcap" "host $TARGET_IP"
  else
    quote_cmd tcpdump -i "$CAPTURE_IFACE" -nn -w "$pcap" "host $TARGET_IP"
  fi
  if [[ "$DRY_RUN" == "1" ]]; then
    return
  fi
  if [[ -n "$SUDO" ]]; then
    "$SUDO" tcpdump -i "$CAPTURE_IFACE" -nn -w "$pcap" "host $TARGET_IP" \
      >"$LOG_DIR/tcpdump_$(basename "$pcap" .pcap).log" 2>&1 &
  else
    tcpdump -i "$CAPTURE_IFACE" -nn -w "$pcap" "host $TARGET_IP" \
      >"$LOG_DIR/tcpdump_$(basename "$pcap" .pcap).log" 2>&1 &
  fi
  TCPDUMP_PID="$!"
  sleep 2
}

stop_capture() {
  if [[ -z "$TCPDUMP_PID" ]]; then
    return
  fi
  phase "Stop Capture"
  if [[ "$DRY_RUN" != "1" ]]; then
    kill -INT "$TCPDUMP_PID" >/dev/null 2>&1 || true
    wait "$TCPDUMP_PID" >/dev/null 2>&1 || true
  fi
  TCPDUMP_PID=""
}

cleanup() {
  stop_capture
  if [[ -n "$TARGET_PID" ]]; then
    kill "$TARGET_PID" >/dev/null 2>&1 || true
    wait "$TARGET_PID" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --check-only)
      CHECK_ONLY=1
      shift
      ;;
    --train)
      TRAIN=1
      shift
      ;;
    --target-ip)
      TARGET_IP="$2"
      TARGET_URL="http://${TARGET_IP}:${TARGET_PORT}/"
      shift 2
      ;;
    --target-port)
      TARGET_PORT="$2"
      TARGET_URL="http://${TARGET_IP}:${TARGET_PORT}/"
      shift 2
      ;;
    --target-url)
      TARGET_URL="$2"
      shift 2
      ;;
    --iface)
      CAPTURE_IFACE="$2"
      shift 2
      ;;
    --run-id)
      RUN_ID="$2"
      PCAP_DIR="data/pcap/${RUN_ID}"
      FEATURE_DIR="data/features/${RUN_ID}"
      LOG_DIR="data/logs/${RUN_ID}"
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

validate_safety
preflight

if [[ "$CHECK_ONLY" == "1" ]]; then
  log "Contract check completed."
  exit 0
fi

ensure_dirs

NORMAL_PCAP="$PCAP_DIR/normal_${RUN_ID}.pcap"
NORMAL_CSV="$FEATURE_DIR/normal_${RUN_ID}.csv"
ATTACK_BEFORE_PCAP="$PCAP_DIR/attack_before_defense_${RUN_ID}.pcap"
ATTACK_BEFORE_CSV="$FEATURE_DIR/attack_before_defense_${RUN_ID}.csv"
ATTACK_AFTER_PCAP="$PCAP_DIR/attack_after_defense_${RUN_ID}.pcap"
ATTACK_AFTER_CSV="$FEATURE_DIR/attack_after_defense_${RUN_ID}.csv"
DECISION_JSON="$LOG_DIR/decision_${RUN_ID}.json"

if [[ "$TRAIN" == "1" ]]; then
  phase "Train Model"
  run_cmd "$PYTHON" models/train_mlp.py \
    --input "$TRAIN_FEATURES" \
    --output "$MODEL_PATH" \
    --metrics-out "$LOG_DIR/train_metrics_${RUN_ID}.json"
fi

start_target_server
check_target_url

phase "Reset Defense Rules"
run_cmd bash defense/unblock_all.sh --project-tag "$PROJECT_TAG"
run_cmd bash defense/show_rules.sh --project-tag "$PROJECT_TAG"

phase "Generate Normal Traffic"
start_capture "$NORMAL_PCAP"
run_cmd "$PYTHON" attacks/normal_traffic.py \
  --target-url "$TARGET_URL" \
  --duration "$NORMAL_SECONDS" \
  --rate "$NORMAL_RATE" \
  --output "$LOG_DIR/normal_traffic_${RUN_ID}.log"
stop_capture
run_cmd "$PYTHON" features/extract_features.py \
  --input "$NORMAL_PCAP" \
  --output "$NORMAL_CSV" \
  --label normal \
  --attack-type normal \
  --target-ip "$TARGET_IP" \
  --window-size "$FEATURE_WINDOW"

phase "Run Attack Before Defense"
start_capture "$ATTACK_BEFORE_PCAP"
run_cmd bash attacks/run_mixed_attack.sh \
  --target-ip "$TARGET_IP" \
  --target-port "$TARGET_PORT" \
  --target-url "$TARGET_URL" \
  --duration "$ATTACK_SECONDS" \
  --syn-rate "$SYN_RATE" \
  --http-rate "$HTTP_RATE" \
  --udp-rate "$UDP_RATE" \
  --output-dir "$LOG_DIR"
stop_capture

phase "Infer Attack And Apply Defense"
run_cmd "$PYTHON" features/extract_features.py \
  --input "$ATTACK_BEFORE_PCAP" \
  --output "$ATTACK_BEFORE_CSV" \
  --label attack \
  --attack-type mixed_attack \
  --target-ip "$TARGET_IP" \
  --window-size "$FEATURE_WINDOW"
run_cmd "$PYTHON" models/infer.py \
  --input "$ATTACK_BEFORE_CSV" \
  --model "$MODEL_PATH" \
  --output "$DECISION_JSON" \
  --threshold "$CONFIDENCE_THRESHOLD"
run_cmd bash defense/iptables_rules.sh \
  --target-port "$TARGET_PORT" \
  --syn-rate "$SYN_LIMIT" \
  --http-rate "$HTTP_LIMIT" \
  --project-tag "$PROJECT_TAG"
run_cmd "$PYTHON" defense/apply_decision.py \
  --decision "$DECISION_JSON" \
  --threshold "$CONFIDENCE_THRESHOLD" \
  --block-script defense/block_ip.sh \
  --project-tag "$PROJECT_TAG"
run_cmd bash defense/show_rules.sh --project-tag "$PROJECT_TAG"

phase "Run Same Attack After Defense"
start_capture "$ATTACK_AFTER_PCAP"
run_cmd bash attacks/run_mixed_attack.sh \
  --target-ip "$TARGET_IP" \
  --target-port "$TARGET_PORT" \
  --target-url "$TARGET_URL" \
  --duration "$ATTACK_SECONDS" \
  --syn-rate "$SYN_RATE" \
  --http-rate "$HTTP_RATE" \
  --udp-rate "$UDP_RATE" \
  --output-dir "$LOG_DIR"
stop_capture
run_cmd "$PYTHON" features/extract_features.py \
  --input "$ATTACK_AFTER_PCAP" \
  --output "$ATTACK_AFTER_CSV" \
  --label attack \
  --attack-type mixed_attack_after_defense \
  --target-ip "$TARGET_IP" \
  --window-size "$FEATURE_WINDOW"
run_cmd bash defense/show_rules.sh --project-tag "$PROJECT_TAG"

if storage_is_enabled; then
  phase "Persist Demo Summary"
  run_cmd "$PYTHON" scripts/persist_demo_summary.py \
    --run-id "$RUN_ID" \
    --target-ip "$TARGET_IP" \
    --target-port "$TARGET_PORT" \
    --target-url "$TARGET_URL" \
    --pcap-dir "$PCAP_DIR" \
    --feature-dir "$FEATURE_DIR" \
    --log-dir "$LOG_DIR" \
    --normal-pcap "$NORMAL_PCAP" \
    --normal-csv "$NORMAL_CSV" \
    --attack-before-pcap "$ATTACK_BEFORE_PCAP" \
    --attack-before-csv "$ATTACK_BEFORE_CSV" \
    --attack-after-pcap "$ATTACK_AFTER_PCAP" \
    --attack-after-csv "$ATTACK_AFTER_CSV" \
    --decision-json "$DECISION_JSON" \
    --project-tag "$PROJECT_TAG"
fi

phase "Demo Outputs"
log "PCAP files:      $PCAP_DIR"
log "Feature CSVs:    $FEATURE_DIR"
log "Logs/decisions:  $LOG_DIR"
log "Decision JSON:   $DECISION_JSON"
if storage_is_enabled; then
  log "Redis storage:   ${REDIS_URL} (prefix=${STORAGE_KEY_PREFIX}, run=${RUN_ID})"
fi
log "To clean rules:  bash defense/unblock_all.sh --project-tag $PROJECT_TAG"
