#!/usr/bin/env python3
"""Append a live demo event to Redis."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from storage.redis_store import StorageError, persist_live_event


def parse_field(values: list[str]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for item in values:
        if "=" not in item:
            raise ValueError(f"invalid --field value {item!r}; expected key=value")
        key, value = item.split("=", 1)
        fields[key] = value
    return fields


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Persist a live demo event.")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--phase", default="")
    parser.add_argument("--label", default="")
    parser.add_argument("--attack-type", default="")
    parser.add_argument("--phase-file", default="")
    parser.add_argument("--field", action="append", default=[], help="Extra key=value field.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        payload = {
            "event": args.event,
            "phase": args.phase,
            "label": args.label,
            "attack_type": args.attack_type,
            **parse_field(args.field),
        }
        if args.phase_file:
            phase_path = Path(args.phase_file)
            phase_path.parent.mkdir(parents=True, exist_ok=True)
            phase_path.write_text(
                json.dumps(
                    {
                        "phase": args.phase,
                        "label": args.label,
                        "attack_type": args.attack_type,
                    },
                    ensure_ascii=True,
                ),
                encoding="utf-8",
            )
        info = persist_live_event(payload, run_id=args.run_id)
    except (ValueError, OSError, StorageError) as exc:
        print(f"[live][error] {exc}", file=sys.stderr, flush=True)
        return 1

    if info is not None:
        print(
            "Stored live event in Redis: "
            f"run={info['run_id']} event={args.event} key={info['key']}",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
