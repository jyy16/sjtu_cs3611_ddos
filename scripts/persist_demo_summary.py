#!/usr/bin/env python3
"""Persist the final demo summary to the configured structured storage backend."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from storage.redis_store import StorageError, persist_demo_summary


def _existing_paths(paths: dict[str, str]) -> dict[str, bool]:
    return {name: Path(path).exists() for name, path in paths.items() if path}


def _decision_count(path: str) -> int:
    decision_path = Path(path)
    if not decision_path.is_file():
        return 0
    with decision_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    decisions = payload.get("decisions", [])
    return len(decisions) if isinstance(decisions, list) else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Persist final Project 9 demo summary.")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--target-ip", required=True)
    parser.add_argument("--target-port", required=True)
    parser.add_argument("--target-url", required=True)
    parser.add_argument("--pcap-dir", required=True)
    parser.add_argument("--feature-dir", required=True)
    parser.add_argument("--log-dir", required=True)
    parser.add_argument("--normal-pcap", required=True)
    parser.add_argument("--normal-csv", required=True)
    parser.add_argument("--attack-before-pcap", required=True)
    parser.add_argument("--attack-before-csv", required=True)
    parser.add_argument("--attack-after-pcap", required=True)
    parser.add_argument("--attack-after-csv", required=True)
    parser.add_argument("--decision-json", required=True)
    parser.add_argument("--project-tag", required=True)
    parser.add_argument("--status", default="completed")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = {
        "pcap_dir": args.pcap_dir,
        "feature_dir": args.feature_dir,
        "log_dir": args.log_dir,
        "normal_pcap": args.normal_pcap,
        "normal_csv": args.normal_csv,
        "attack_before_pcap": args.attack_before_pcap,
        "attack_before_csv": args.attack_before_csv,
        "attack_after_pcap": args.attack_after_pcap,
        "attack_after_csv": args.attack_after_csv,
        "decision_json": args.decision_json,
    }
    try:
        decision_count = _decision_count(args.decision_json)
        info = persist_demo_summary(
            {
                "run_id": args.run_id,
                "status": args.status,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "target_ip": args.target_ip,
                "target_port": args.target_port,
                "target_url": args.target_url,
                "project_tag": args.project_tag,
                "decision_count": decision_count,
                "paths": paths,
                "path_exists": _existing_paths(paths),
            },
            run_id=args.run_id,
        )
    except (OSError, json.JSONDecodeError, StorageError) as exc:
        print(f"[storage][error] {exc}", file=sys.stderr, flush=True)
        return 1

    if info is not None:
        print(
            "Stored demo summary in Redis: "
            f"run={info['run_id']} artifact={info['artifact']} key={info['key']}",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
