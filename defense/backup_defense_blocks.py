#!/usr/bin/env python3
"""Back up defense/block_ip.sh execution logs to Redis."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from storage.redis_store import StorageError, persist_defense_block_log, storage_enabled


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Persist defense_blocks.log entries to the configured Redis storage backend."
    )
    parser.add_argument(
        "--log",
        required=True,
        help="Path to defense_blocks.log.",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="Run id to use in Redis keys. Defaults to RUN_ID or path-derived id.",
    )
    parser.add_argument(
        "--artifact",
        default="defense_blocks",
        help="Artifact name stored in Redis metadata. Default: defense_blocks.",
    )
    return parser.parse_args()


def parse_log_line(line: str, index: int) -> dict[str, Any] | None:
    text = line.strip()
    if not text:
        return None

    parts = text.split(",")
    record: dict[str, Any] = {
        "log_index": index,
        "timestamp": parts[0].strip(),
    }
    for part in parts[1:]:
        key, separator, value = part.partition("=")
        if not separator:
            continue
        key = key.strip()
        value = value.strip()
        if key == "ip":
            record["src_ip"] = value
        elif key == "tag":
            record["project_tag"] = value
        else:
            record[key] = value

    return record


def read_block_log(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    records: list[dict[str, Any]] = []
    for index, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines()):
        record = parse_log_line(line, index)
        if record is not None:
            records.append(record)
    return records


def main() -> int:
    args = parse_args()
    log_path = Path(args.log)
    records = read_block_log(log_path)

    if not storage_enabled():
        print(
            f"[storage] STORAGE_BACKEND is disabled; parsed {len(records)} defense block log row(s) but did not persist."
        )
        return 0

    try:
        info = persist_defense_block_log(
            records,
            log_path=log_path,
            run_id=args.run_id,
            artifact=args.artifact,
        )
    except StorageError as exc:
        print(f"[storage][error] {exc}", flush=True)
        return 1

    if info is None:
        print(
            f"[storage] Storage backend skipped; parsed {len(records)} defense block log row(s)."
        )
        return 0

    print(
        "Stored defense block log in Redis: "
        f"run={info['run_id']} artifact={info['artifact']} key={info['key']} rows={info['rows']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
