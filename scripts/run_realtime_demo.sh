#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="${ENV_FILE:-scripts/demo.env}"
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source <(sed 's/\r$//' "$ENV_FILE")
  set +a
fi

PYTHON="${PYTHON:-python3}"
SUDO="${SUDO-sudo}"

TARGET_IP="${TARGET_IP:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-8080}"
TARGET_URL="${TARGET_URL:-http://${TARGET_IP}:${TARGET_PORT}/}"
CAPTURE_IFACE="${CAPTURE_IFACE:-lo}"

RUN_ID="${RUN_ID:-realtime_$(date +%Y%m%d_%H%M%S)}"
PROJECT_TAG="${PROJECT_TAG:-cs3611-ddos}"

NORMAL_SECONDS="${NORMAL_SECONDS:-10}"
ATTACK_SECONDS="${REALTIME_ATTACK_SECONDS:-${ATTACK_SECONDS:-120}}"
NORMAL_RATE="${NORMAL_RATE:-5}"
SYN_RATE="${SYN_RATE:-200}"
HTTP_RATE="${HTTP_RATE:-80}"
UDP_RATE="${UDP_RATE:-100}"
SYN_LIMIT="${SYN_LIMIT:-50}"
HTTP_LIMIT="${HTTP_LIMIT:-120}"
FEATURE_WINDOW="${FEATURE_WINDOW:-1}"
CONFIDENCE_THRESHOLD="${CONFIDENCE_THRESHOLD:-0.80}"
REALTIME_WINDOW_SECONDS="${REALTIME_WINDOW_SECONDS:-4}"
REALTIME_GRACE_SECONDS="${REALTIME_GRACE_SECONDS:-2}"
TCPDUMP_WARMUP_SECONDS="${TCPDUMP_WARMUP_SECONDS:-1}"
DEFENSE_TTL="${DEFENSE_TTL:-300}"
INSTALL_BASELINE="${INSTALL_BASELINE:-0}"

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
RT_PCAP_DIR="${PCAP_DIR}/realtime_windows"
RT_FEATURE_DIR="${FEATURE_DIR}/realtime_windows"
RT_DECISION_DIR="${LOG_DIR}/realtime_decisions"

DEFENSE_LOG_DIR="$LOG_DIR"
export RUN_ID STORAGE_BACKEND REDIS_URL STORAGE_KEY_PREFIX STORAGE_FAIL_OPEN
export TARGET_IP TARGET_PORT DEFENSE_LOG_DIR

TARGET_PID=""
NORMAL_TCPDUMP_PID=""
ATTACK_TCPDUMP_PID=""
DEFENSE_PID=""

usage() {
  cat <<'EOF'
Usage:
  bash scripts/run_realtime_demo.sh [options]

Run a realtime demo where the mixed attack stays in the foreground while
AI inference and automatic blocking run in a background loop.

Options:
  --dry-run                 Print commands without executing them.
  --check-only              Check required files and commands, then exit.
  --train                   Run model training before the live demo.
  --target-ip IP            Victim IP. Must be loopback or private IPv4.
  --target-port PORT        Victim HTTP port.
  --target-url URL          Victim HTTP URL.
  --iface IFACE             tcpdump capture interface, for example lo, any, or h1-eth0.
  --run-id ID               Output folder suffix.
  --window-seconds SEC      Realtime defense window length. Default: 4.
  --defense-ttl SEC         Block TTL passed to defense/apply_decision.py. Default: 300.
  --baseline                Install baseline rate-limit rules before the attack.
  --no-baseline             Skip baseline rules and show only model-driven blocking. Default.
  -h, --help                Show this help.

Typical realtime local demo:
  cp scripts/demo.env.example scripts/demo.env
  bash scripts/run_realtime_demo.sh --check-only
  bash scripts/run_realtime_demo.sh --run-id realtime_demo_01

Slow machines may need a longer foreground attack so the first model decision
and block action are visible while the attack is still running:
  REALTIME_ATTACK_SECONDS=180 bash scripts/run_realtime_demo.sh --run-id realtime_demo_02

Visualize the realtime run:
  python3 scripts/visualize_realtime_demo.py --run-id realtime_demo_01

Typical Mininet realtime demo:
  START_TARGET=0 TARGET_IP=10.0.0.2 TARGET_PORT=80 TARGET_URL=http://10.0.0.2/ CAPTURE_IFACE=h1-eth0 bash scripts/run_realtime_demo.sh --run-id mininet_realtime_01
EOF
}

log() {
  printf '[realtime-demo] %s\n' "$*"
}

phase() {
  printf '\n========== %s ==========\n' "$*"
}

die() {
  printf '[realtime-demo][error] %s\n' "$*" >&2
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

is_uint() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
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
  is_uint "$TARGET_PORT" || die "TARGET_PORT must be numeric: $TARGET_PORT"
  [[ "$TARGET_PORT" -ge 1 && "$TARGET_PORT" -le 65535 ]] || die "TARGET_PORT out of range: $TARGET_PORT"
  is_uint "$NORMAL_SECONDS" || die "NORMAL_SECONDS must be numeric: $NORMAL_SECONDS"
  is_uint "$ATTACK_SECONDS" || die "ATTACK_SECONDS must be numeric: $ATTACK_SECONDS"
  is_uint "$REALTIME_WINDOW_SECONDS" || die "REALTIME_WINDOW_SECONDS must be numeric: $REALTIME_WINDOW_SECONDS"
  is_uint "$REALTIME_GRACE_SECONDS" || die "REALTIME_GRACE_SECONDS must be numeric: $REALTIME_GRACE_SECONDS"
  is_uint "$DEFENSE_TTL" || die "DEFENSE_TTL must be numeric: $DEFENSE_TTL"
  [[ "$REALTIME_WINDOW_SECONDS" -ge 1 ]] || die "REALTIME_WINDOW_SECONDS must be greater than 0"
  [[ "$DEFENSE_TTL" -ge 1 ]] || die "DEFENSE_TTL must be greater than 0"
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
  need_file attacks/run_mixed_attack.sh
  need_file defense/unblock_all.sh
  need_file defense/iptables_rules.sh
  need_file defense/show_rules.sh
  need_file defense/block_ip.sh
  need_file defense/apply_decision.py
  need_file defense/backup_defense_blocks.py
  need_file features/extract_features.py
  need_file models/train_mlp.py
  need_file models/infer.py
  need_file scripts/visualize_realtime_demo.py

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
  mkdir -p "$PCAP_DIR" "$FEATURE_DIR" "$LOG_DIR" "$RT_PCAP_DIR" "$RT_FEATURE_DIR" "$RT_DECISION_DIR" models/saved
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

start_tcpdump() {
  local pcap="$1"
  local log_path="$2"
  local pid_var="$3"

  mkdir -p "$(dirname "$pcap")" "$(dirname "$log_path")"
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
      >"$log_path" 2>&1 &
  else
    tcpdump -i "$CAPTURE_IFACE" -nn -w "$pcap" "host $TARGET_IP" \
      >"$log_path" 2>&1 &
  fi
  printf -v "$pid_var" '%s' "$!"
  sleep "$TCPDUMP_WARMUP_SECONDS"

  local pid_value
  pid_value="${!pid_var:-}"
  if [[ -n "$pid_value" ]] && ! kill -0 "$pid_value" >/dev/null 2>&1; then
    die "tcpdump failed to start for $pcap; see $log_path"
  fi
}

stop_pid() {
  local pid="${1:-}"
  local signal="${2:-INT}"

  if [[ -z "$pid" || "$DRY_RUN" == "1" ]]; then
    return
  fi
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill "-$signal" "$pid" >/dev/null 2>&1 || true
  fi
  wait "$pid" >/dev/null 2>&1 || true
}

csv_has_rows() {
  local path="$1"
  local line_count

  [[ -f "$path" ]] || return 1
  line_count="$(wc -l < "$path" | tr -d '[:space:]')"
  [[ "${line_count:-0}" -gt 1 ]]
}

merge_realtime_decisions() {
  local output_path="$1"

  if [[ "$DRY_RUN" == "1" ]]; then
    quote_cmd "$PYTHON" - "$RT_DECISION_DIR" "$output_path" "$CONFIDENCE_THRESHOLD"
    return
  fi

  "$PYTHON" - "$RT_DECISION_DIR" "$output_path" "$CONFIDENCE_THRESHOLD" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

decision_dir = Path(sys.argv[1])
output_path = Path(sys.argv[2])
threshold = float(sys.argv[3])

all_decisions = []
best_by_source_action = {}

for path in sorted(decision_dir.glob("decision_window_*.json")):
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        continue
    for decision in payload.get("decisions", []):
        if not isinstance(decision, dict):
            continue
        item = dict(decision)
        item["window"] = path.stem
        item["decision_path"] = str(path)
        all_decisions.append(item)
        key = (item.get("src_ip", ""), item.get("action", ""))
        confidence = float(item.get("confidence") or 0.0)
        previous = best_by_source_action.get(key)
        previous_confidence = float((previous or {}).get("confidence") or 0.0)
        if previous is None or confidence > previous_confidence:
            best_by_source_action[key] = item

deduped = sorted(
    best_by_source_action.values(),
    key=lambda item: (str(item.get("src_ip", "")), str(item.get("action", ""))),
)
report = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "mode": "realtime",
    "threshold": threshold,
    "window_decision_count": len(all_decisions),
    "decisions": deduped,
    "all_window_decisions": all_decisions,
}
output_path.parent.mkdir(parents=True, exist_ok=True)
output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"Merged {len(all_decisions)} realtime window decisions into {output_path}")
PY
}

run_realtime_defense_loop() {
  local deadline
  local index=1
  local current_window_pid=""
  local summary_csv="$LOG_DIR/realtime_window_summary_${RUN_ID}.csv"

  trap 'if [[ -n "${current_window_pid:-}" ]]; then kill -INT "$current_window_pid" >/dev/null 2>&1 || true; wait "$current_window_pid" >/dev/null 2>&1 || true; fi' EXIT INT TERM

  printf 'window,capture_started_at,capture_seconds,pcap,csv,decision,extract_status,infer_status,apply_status\n' >"$summary_csv"
  deadline=$(($(date +%s) + ATTACK_SECONDS + REALTIME_GRACE_SECONDS))
  log "Realtime defense loop started: window=${REALTIME_WINDOW_SECONDS}s ttl=${DEFENSE_TTL}s deadline=${deadline}"

  while [[ "$(date +%s)" -lt "$deadline" ]]; do
    local now remaining capture_seconds idx pcap csv decision_json
    local tcpdump_log extract_log infer_log apply_log started_at
    local extract_status="skipped" infer_status="skipped" apply_status="skipped"

    now="$(date +%s)"
    remaining=$((deadline - now))
    capture_seconds="$REALTIME_WINDOW_SECONDS"
    if [[ "$capture_seconds" -gt "$remaining" ]]; then
      capture_seconds="$remaining"
    fi
    [[ "$capture_seconds" -ge 1 ]] || break

    idx="$(printf '%03d' "$index")"
    pcap="$RT_PCAP_DIR/window_${idx}_${RUN_ID}.pcap"
    csv="$RT_FEATURE_DIR/window_${idx}_${RUN_ID}.csv"
    decision_json="$RT_DECISION_DIR/decision_window_${idx}_${RUN_ID}.json"
    tcpdump_log="$LOG_DIR/tcpdump_realtime_window_${idx}_${RUN_ID}.log"
    extract_log="$LOG_DIR/extract_realtime_window_${idx}_${RUN_ID}.log"
    infer_log="$LOG_DIR/infer_realtime_window_${idx}_${RUN_ID}.log"
    apply_log="$LOG_DIR/apply_realtime_window_${idx}_${RUN_ID}.log"
    started_at="$(date -Iseconds 2>/dev/null || date)"

    log "window ${idx}: capturing ${capture_seconds}s while attack continues"
    start_tcpdump "$pcap" "$tcpdump_log" current_window_pid
    sleep "$capture_seconds"
    stop_pid "$current_window_pid" INT
    current_window_pid=""

    if [[ -s "$pcap" ]]; then
      if "$PYTHON" features/extract_features.py \
        --input "$pcap" \
        --output "$csv" \
        --label attack \
        --attack-type mixed_attack_realtime_window \
        --target-ip "$TARGET_IP" \
        --window-size "$FEATURE_WINDOW" \
        >"$extract_log" 2>&1; then
        extract_status="ok"
      else
        extract_status="failed"
      fi
    else
      extract_status="empty_pcap"
    fi

    if [[ "$extract_status" == "ok" ]] && csv_has_rows "$csv"; then
      if "$PYTHON" models/infer.py \
        --input "$csv" \
        --model "$MODEL_PATH" \
        --output "$decision_json" \
        --threshold "$CONFIDENCE_THRESHOLD" \
        >"$infer_log" 2>&1; then
        infer_status="ok"
      else
        infer_status="failed"
      fi
    elif [[ "$extract_status" == "ok" ]]; then
      infer_status="no_feature_rows"
    fi

    if [[ "$infer_status" == "ok" ]]; then
      if "$PYTHON" defense/apply_decision.py \
        --decision "$decision_json" \
        --threshold "$CONFIDENCE_THRESHOLD" \
        --block-script defense/block_ip.sh \
        --project-tag "$PROJECT_TAG" \
        --ttl "$DEFENSE_TTL" \
        >"$apply_log" 2>&1; then
        apply_status="ok"
      else
        apply_status="failed"
      fi
    fi

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$idx" "$started_at" "$capture_seconds" "$pcap" "$csv" "$decision_json" \
      "$extract_status" "$infer_status" "$apply_status" >>"$summary_csv"
    log "window ${idx}: extract=${extract_status} infer=${infer_status} apply=${apply_status}"
    index=$((index + 1))
  done

  merge_realtime_decisions "$LOG_DIR/decision_realtime_${RUN_ID}.json"
  log "Realtime defense loop finished."
}

cleanup() {
  if [[ -n "$DEFENSE_PID" ]]; then
    kill "$DEFENSE_PID" >/dev/null 2>&1 || true
    wait "$DEFENSE_PID" >/dev/null 2>&1 || true
    DEFENSE_PID=""
  fi
  stop_pid "$ATTACK_TCPDUMP_PID" INT
  ATTACK_TCPDUMP_PID=""
  stop_pid "$NORMAL_TCPDUMP_PID" INT
  NORMAL_TCPDUMP_PID=""
  if [[ -n "$TARGET_PID" ]]; then
    kill "$TARGET_PID" >/dev/null 2>&1 || true
    wait "$TARGET_PID" >/dev/null 2>&1 || true
    TARGET_PID=""
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
      RT_PCAP_DIR="${PCAP_DIR}/realtime_windows"
      RT_FEATURE_DIR="${FEATURE_DIR}/realtime_windows"
      RT_DECISION_DIR="${LOG_DIR}/realtime_decisions"
      DEFENSE_LOG_DIR="$LOG_DIR"
      export RUN_ID DEFENSE_LOG_DIR
      shift 2
      ;;
    --window-seconds)
      REALTIME_WINDOW_SECONDS="$2"
      shift 2
      ;;
    --defense-ttl)
      DEFENSE_TTL="$2"
      shift 2
      ;;
    --baseline)
      INSTALL_BASELINE=1
      shift
      ;;
    --no-baseline)
      INSTALL_BASELINE=0
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

validate_safety
preflight

if [[ "$CHECK_ONLY" == "1" ]]; then
  log "Realtime contract check completed."
  exit 0
fi

ensure_dirs
export DEFENSE_LOG_DIR TARGET_IP TARGET_PORT

NORMAL_PCAP="$PCAP_DIR/normal_${RUN_ID}.pcap"
NORMAL_CSV="$FEATURE_DIR/normal_${RUN_ID}.csv"
REALTIME_ATTACK_PCAP="$PCAP_DIR/attack_realtime_defense_${RUN_ID}.pcap"
REALTIME_ATTACK_CSV="$FEATURE_DIR/attack_realtime_defense_${RUN_ID}.csv"
REALTIME_DECISION_JSON="$LOG_DIR/decision_realtime_${RUN_ID}.json"

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
if [[ "$INSTALL_BASELINE" == "1" ]]; then
  run_cmd bash defense/iptables_rules.sh \
    --target-port "$TARGET_PORT" \
    --syn-rate "$SYN_LIMIT" \
    --http-rate "$HTTP_LIMIT" \
    --project-tag "$PROJECT_TAG"
fi
run_cmd bash defense/show_rules.sh --project-tag "$PROJECT_TAG"

phase "Generate Normal Traffic Baseline"
start_tcpdump "$NORMAL_PCAP" "$LOG_DIR/tcpdump_normal_${RUN_ID}.log" NORMAL_TCPDUMP_PID
run_cmd "$PYTHON" attacks/normal_traffic.py \
  --target-url "$TARGET_URL" \
  --duration "$NORMAL_SECONDS" \
  --rate "$NORMAL_RATE" \
  --output "$LOG_DIR/normal_traffic_${RUN_ID}.log"
stop_pid "$NORMAL_TCPDUMP_PID" INT
NORMAL_TCPDUMP_PID=""
run_cmd "$PYTHON" features/extract_features.py \
  --input "$NORMAL_PCAP" \
  --output "$NORMAL_CSV" \
  --label normal \
  --attack-type normal \
  --target-ip "$TARGET_IP" \
  --window-size "$FEATURE_WINDOW"

phase "Run Mixed Attack With Realtime Defense"
start_tcpdump "$REALTIME_ATTACK_PCAP" "$LOG_DIR/tcpdump_attack_realtime_defense_${RUN_ID}.log" ATTACK_TCPDUMP_PID

if [[ "$DRY_RUN" == "1" ]]; then
  quote_cmd bash -c "run_realtime_defense_loop > '$LOG_DIR/realtime_defense_loop_${RUN_ID}.log' 2>&1 &"
else
  run_realtime_defense_loop >"$LOG_DIR/realtime_defense_loop_${RUN_ID}.log" 2>&1 &
  DEFENSE_PID="$!"
  log "Realtime defense loop is running in background: pid=${DEFENSE_PID}, log=${LOG_DIR}/realtime_defense_loop_${RUN_ID}.log"
fi

quote_cmd bash attacks/run_mixed_attack.sh \
  --target-ip "$TARGET_IP" \
  --target-port "$TARGET_PORT" \
  --target-url "$TARGET_URL" \
  --duration "$ATTACK_SECONDS" \
  --syn-rate "$SYN_RATE" \
  --http-rate "$HTTP_RATE" \
  --udp-rate "$UDP_RATE" \
  --output-dir "$LOG_DIR"

ATTACK_STATUS=0
if [[ "$DRY_RUN" != "1" ]]; then
  set +e
  bash attacks/run_mixed_attack.sh \
    --target-ip "$TARGET_IP" \
    --target-port "$TARGET_PORT" \
    --target-url "$TARGET_URL" \
    --duration "$ATTACK_SECONDS" \
    --syn-rate "$SYN_RATE" \
    --http-rate "$HTTP_RATE" \
    --udp-rate "$UDP_RATE" \
    --output-dir "$LOG_DIR"
  ATTACK_STATUS=$?
  set -e
fi

stop_pid "$ATTACK_TCPDUMP_PID" INT
ATTACK_TCPDUMP_PID=""

DEFENSE_STATUS=0
if [[ -n "$DEFENSE_PID" ]]; then
  set +e
  wait "$DEFENSE_PID"
  DEFENSE_STATUS=$?
  set -e
  DEFENSE_PID=""
fi

run_cmd "$PYTHON" features/extract_features.py \
  --input "$REALTIME_ATTACK_PCAP" \
  --output "$REALTIME_ATTACK_CSV" \
  --label attack \
  --attack-type mixed_attack_realtime_defense \
  --target-ip "$TARGET_IP" \
  --window-size "$FEATURE_WINDOW"
run_cmd bash defense/show_rules.sh --project-tag "$PROJECT_TAG"
run_cmd "$PYTHON" defense/backup_defense_blocks.py \
  --log "$LOG_DIR/defense_blocks.log" \
  --run-id "$RUN_ID" \
  --artifact "defense_blocks_${RUN_ID}"

if [[ "$ATTACK_STATUS" -ne 0 ]]; then
  die "Mixed attack exited with status $ATTACK_STATUS. Realtime artifacts may be partial under $LOG_DIR."
fi
if [[ "$DEFENSE_STATUS" -ne 0 ]]; then
  die "Realtime defense loop exited with status $DEFENSE_STATUS. See $LOG_DIR/realtime_defense_loop_${RUN_ID}.log."
fi

phase "Realtime Demo Outputs"
log "PCAP files:          $PCAP_DIR"
log "Feature CSVs:        $FEATURE_DIR"
log "Logs/decisions:      $LOG_DIR"
log "Realtime decisions:  $REALTIME_DECISION_JSON"
log "Defense loop log:    $LOG_DIR/realtime_defense_loop_${RUN_ID}.log"
log "Visualization:       $PYTHON scripts/visualize_realtime_demo.py --run-id $RUN_ID"
if storage_is_enabled; then
  log "Redis storage:       ${REDIS_URL} (prefix=${STORAGE_KEY_PREFIX}, run=${RUN_ID})"
fi
log "To clean rules:      bash defense/unblock_all.sh --project-tag $PROJECT_TAG"
