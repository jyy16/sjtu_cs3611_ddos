#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON="${PYTHON:-python3}"
GROUP="${1:-}"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/check_group_contract.sh attack
  bash scripts/check_group_contract.sh defense
  bash scripts/check_group_contract.sh model

This script only checks that required files exist and that each command supports --help.
It does not generate traffic, change firewall rules, train a model, or read PCAP files.
EOF
}

if [[ -z "$GROUP" || "$GROUP" == "-h" || "$GROUP" == "--help" ]]; then
  usage
  exit 0
fi

missing=()
failed_help=()
files=()
commands=()

case "$GROUP" in
  attack)
    files=(
      attacks/normal_traffic.py
      attacks/syn_flood.py
      attacks/http_flood.py
      attacks/udp_reflection_sim.py
      attacks/run_mixed_attack.sh
    )
    commands=(
      "$PYTHON attacks/normal_traffic.py --help"
      "$PYTHON attacks/syn_flood.py --help"
      "$PYTHON attacks/http_flood.py --help"
      "$PYTHON attacks/udp_reflection_sim.py --help"
      "bash attacks/run_mixed_attack.sh --help"
    )
    ;;
  defense)
    files=(
      defense/unblock_all.sh
      defense/iptables_rules.sh
      defense/show_rules.sh
      defense/block_ip.sh
      defense/apply_decision.py
    )
    commands=(
      "bash defense/unblock_all.sh --help"
      "bash defense/iptables_rules.sh --help"
      "bash defense/show_rules.sh --help"
      "bash defense/block_ip.sh --help"
      "$PYTHON defense/apply_decision.py --help"
    )
    ;;
  model)
    files=(
      features/extract_features.py
      features/feature_schema.md
      models/train_mlp.py
      models/infer.py
    )
    commands=(
      "$PYTHON features/extract_features.py --help"
      "$PYTHON models/train_mlp.py --help"
      "$PYTHON models/infer.py --help"
    )
    ;;
  *)
    printf '[contract][error] Unknown group: %s\n' "$GROUP" >&2
    usage
    exit 1
    ;;
esac

for file in "${files[@]}"; do
  if [[ ! -f "$file" ]]; then
    missing+=("$file")
  fi
done

for cmd in "${commands[@]}"; do
  printf '+ %s\n' "$cmd"
  if ! bash -lc "$cmd" >/dev/null 2>&1; then
    failed_help+=("$cmd")
  fi
done

if [[ ${#missing[@]} -gt 0 ]]; then
  printf 'Missing files:\n' >&2
  printf '  %s\n' "${missing[@]}" >&2
fi

if [[ ${#failed_help[@]} -gt 0 ]]; then
  printf 'Commands whose --help failed:\n' >&2
  printf '  %s\n' "${failed_help[@]}" >&2
fi

if [[ ${#missing[@]} -gt 0 || ${#failed_help[@]} -gt 0 ]]; then
  printf '[contract][error] %s group contract check failed.\n' "$GROUP" >&2
  exit 1
fi

printf '[contract] %s group contract check passed.\n' "$GROUP"
