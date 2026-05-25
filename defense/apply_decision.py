#!/usr/bin/env python3
"""Apply model decisions by invoking the defense block script."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


DEFAULT_BLOCK_TTL = 300


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read model decision JSON and apply defense actions."
    )
    parser.add_argument(
        "--decision",
        required=True,
        help="Path to model decision JSON.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        required=True,
        help="Minimum confidence required to apply a block action.",
    )
    parser.add_argument(
        "--block-script",
        required=True,
        help="Path to defense/block_ip.sh.",
    )
    parser.add_argument(
        "--project-tag",
        required=True,
        help="Comment/tag used to identify project-owned rules.",
    )
    parser.add_argument(
        "--ttl",
        type=int,
        default=DEFAULT_BLOCK_TTL,
        help=f"Block duration passed to block_ip.sh. Default: {DEFAULT_BLOCK_TTL}.",
    )
    return parser.parse_args()


def log(message: str) -> None:
    print(f"[defense] {message}", flush=True)


def error(message: str) -> None:
    print(f"[defense][error] {message}", file=sys.stderr, flush=True)


def warn(message: str) -> None:
    print(f"[defense][warn] {message}", file=sys.stderr, flush=True)


def load_decision(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"decision file does not exist: {path}")

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in decision file: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("decision JSON root must be an object")

    decisions = data.get("decisions")
    if decisions is None:
        data["decisions"] = []
    elif not isinstance(decisions, list):
        raise ValueError('decision JSON field "decisions" must be a list')

    return data


def as_float(value: Any, field: str, index: int) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        warn(f"decision[{index}] skipped: {field} is not numeric")
        return None


def build_reason(decision: dict[str, Any]) -> str:
    reason = str(decision.get("reason") or "").strip()
    if reason:
        return reason

    attack_type = str(decision.get("attack_type") or "").strip()
    if attack_type:
        return f"model_detected_{attack_type}"

    return "model_detected_attack"


def iter_block_actions(
    decisions: list[Any],
    threshold: float,
) -> list[tuple[str, str, float]]:
    actions: list[tuple[str, str, float]] = []
    seen_ips: set[str] = set()

    for index, decision in enumerate(decisions):
        if not isinstance(decision, dict):
            warn(f"decision[{index}] skipped: entry is not an object")
            continue

        label = str(decision.get("label") or "").strip().lower()
        if label != "attack":
            log(f"decision[{index}] skipped: label={label or '<missing>'}")
            continue

        confidence = as_float(decision.get("confidence"), "confidence", index)
        if confidence is None:
            continue
        if confidence < threshold:
            log(
                "decision[{index}] skipped: confidence={confidence:.3f} "
                "below threshold={threshold:.3f}".format(
                    index=index,
                    confidence=confidence,
                    threshold=threshold,
                )
            )
            continue

        src_ip = str(decision.get("src_ip") or "").strip()
        if not src_ip:
            warn(f"decision[{index}] skipped: missing src_ip")
            continue

        if src_ip in seen_ips:
            log(f"decision[{index}] skipped: duplicate src_ip={src_ip}")
            continue

        seen_ips.add(src_ip)
        actions.append((src_ip, build_reason(decision), confidence))

    return actions


def run_block_script(
    block_script: Path,
    src_ip: str,
    reason: str,
    ttl: int,
    project_tag: str,
) -> int:
    cmd = [
        "bash",
        str(block_script),
        "--ip",
        src_ip,
        "--reason",
        reason,
        "--ttl",
        str(ttl),
        "--project-tag",
        project_tag,
    ]

    log("running: " + " ".join(cmd))
    completed = subprocess.run(cmd, check=False)
    return completed.returncode


def main() -> int:
    args = parse_args()

    if args.threshold < 0 or args.threshold > 1:
        error("--threshold must be between 0 and 1")
        return 1
    if args.ttl <= 0:
        error("--ttl must be greater than 0")
        return 1

    decision_path = Path(args.decision)
    block_script = Path(args.block_script)
    if not block_script.is_file():
        error(f"block script does not exist: {block_script}")
        return 1

    try:
        payload = load_decision(decision_path)
    except ValueError as exc:
        error(str(exc))
        return 1

    decisions = payload["decisions"]
    actions = iter_block_actions(decisions, args.threshold)
    if not actions:
        log("no attack decisions met the threshold; no defense action applied")
        return 0

    failures = 0
    for src_ip, reason, confidence in actions:
        log(
            "applying defense: "
            f"src_ip={src_ip} confidence={confidence:.3f} reason={reason}"
        )
        returncode = run_block_script(
            block_script=block_script,
            src_ip=src_ip,
            reason=reason,
            ttl=args.ttl,
            project_tag=args.project_tag,
        )
        if returncode != 0:
            failures += 1
            error(f"block script failed for src_ip={src_ip} with exit code {returncode}")

    if failures:
        error(f"{failures} defense action(s) failed")
        return 1

    log(f"applied {len(actions)} defense action(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
