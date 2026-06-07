#!/usr/bin/env python3
"""Stream packet windows from tcpdump into Redis during a live demo."""

from __future__ import annotations

import argparse
import json
import signal
import struct
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterable

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from features.extract_features import PacketRecord, _parse_packet_record, records_to_feature_frame
from storage.redis_store import StorageError, persist_live_event, persist_live_feature_rows


DEFAULT_PHASE = {"phase": "unknown", "label": "attack", "attack_type": "live_capture"}
PRIVATE_PREFIXES = ("127.", "10.", "192.168.")


class LiveCaptureError(RuntimeError):
    pass


def is_private_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(part) for part in parts]
    except ValueError:
        return False
    if any(octet < 0 or octet > 255 for octet in octets):
        return False
    first, second = octets[0], octets[1]
    return (
        ip.startswith(PRIVATE_PREFIXES)
        or (first == 172 and 16 <= second <= 31)
    )


def read_exact(stream: BinaryIO, size: int) -> bytes | None:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_phase(path: Path | None) -> dict[str, str]:
    if path is None or not path.exists():
        return dict(DEFAULT_PHASE)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return dict(DEFAULT_PHASE)
    return {
        "phase": str(payload.get("phase") or DEFAULT_PHASE["phase"]),
        "label": str(payload.get("label") or DEFAULT_PHASE["label"]),
        "attack_type": str(payload.get("attack_type") or DEFAULT_PHASE["attack_type"]),
    }


def phase_key(phase: dict[str, str], window_start: float) -> tuple[float, str, str, str]:
    return (
        window_start,
        phase["phase"],
        phase["label"],
        phase["attack_type"],
    )


def frame_rows(
    records: Iterable[PacketRecord],
    *,
    label: str,
    attack_type: str,
    target_ip: str,
    window_size: float,
    phase: str,
) -> list[dict[str, object]]:
    frame = records_to_feature_frame(
        records=records,
        label=label,
        attack_type=attack_type,
        target_ip=target_ip,
        window_size=window_size,
    )
    rows = frame.to_dict(orient="records")
    for row in rows:
        row["phase"] = phase
    return rows


def parse_global_header(stream: BinaryIO) -> tuple[str, int, int]:
    magic = read_exact(stream, 4)
    if magic is None:
        raise LiveCaptureError("tcpdump ended before writing a PCAP header")
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
        divisor = 1_000_000
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
        divisor = 1_000_000
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian = "<"
        divisor = 1_000_000_000
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian = ">"
        divisor = 1_000_000_000
    else:
        raise LiveCaptureError("tcpdump did not produce a classic PCAP stream")

    header = read_exact(stream, 20)
    if header is None:
        raise LiveCaptureError("tcpdump wrote a truncated PCAP header")
    *_, linktype = struct.unpack(f"{endian}HHIIII", header)
    return endian, divisor, linktype


def build_tcpdump_command(args: argparse.Namespace) -> list[str]:
    command = [args.tcpdump, "-i", args.iface, "-nn", "-U", "-w", "-", f"host {args.target_ip}"]
    if args.sudo_command:
        return [args.sudo_command, *command]
    return command


def start_stderr_logger(process: subprocess.Popen[bytes], log_path: Path | None) -> None:
    if process.stderr is None:
        return

    def drain() -> None:
        handle = None
        try:
            if log_path is not None:
                log_path.parent.mkdir(parents=True, exist_ok=True)
                handle = log_path.open("a", encoding="utf-8")
            for raw in iter(process.stderr.readline, b""):
                text = raw.decode("utf-8", errors="replace")
                if handle is not None:
                    handle.write(text)
                    handle.flush()
                else:
                    sys.stderr.write(text)
                    sys.stderr.flush()
        finally:
            if handle is not None:
                handle.close()

    threading.Thread(target=drain, daemon=True).start()


def persist_event(run_id: str, event: str, **fields: object) -> None:
    persist_live_event({"event": event, **fields}, run_id=run_id)


def run_live_capture(args: argparse.Namespace) -> int:
    if not is_private_ipv4(args.target_ip):
        raise LiveCaptureError(f"target IP must be loopback or private IPv4: {args.target_ip}")

    stop_requested = False
    command = build_tcpdump_command(args)
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    start_stderr_logger(process, Path(args.tcpdump_log) if args.tcpdump_log else None)

    def request_stop(_signum: int, _frame: object) -> None:
        nonlocal stop_requested
        stop_requested = True
        if process.poll() is None:
            process.terminate()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    if process.stdout is None:
        raise LiveCaptureError("tcpdump stdout was not captured")

    phase_path = Path(args.phase_file) if args.phase_file else None
    buckets: dict[tuple[float, str, str, str], list[PacketRecord]] = {}
    total_rows = 0

    persist_event(
        args.run_id,
        "live_capture_started",
        iface=args.iface,
        target_ip=args.target_ip,
        window_size=args.window_size,
    )

    def flush_ready(cutoff_window: float | None = None, *, flush_all: bool = False) -> None:
        nonlocal total_rows
        ready_keys = []
        for key in buckets:
            window_start = key[0]
            if flush_all or (cutoff_window is not None and window_start < cutoff_window):
                ready_keys.append(key)

        for key in sorted(ready_keys):
            window_start, phase, label, attack_type = key
            records = buckets.pop(key)
            rows = frame_rows(
                records,
                label=label,
                attack_type=attack_type,
                target_ip=args.target_ip,
                window_size=args.window_size,
                phase=phase,
            )
            if not rows:
                continue
            info = persist_live_feature_rows(
                rows,
                run_id=args.run_id,
                phase=phase,
                artifact=args.artifact,
            )
            total_rows += len(rows)
            if info is not None:
                print(
                    "Stored live feature rows in Redis: "
                    f"run={info['run_id']} phase={phase} rows={len(rows)} key={info['key']}",
                    flush=True,
                )

    try:
        endian, divisor, linktype = parse_global_header(process.stdout)
        while not stop_requested:
            packet_header = read_exact(process.stdout, 16)
            if packet_header is None:
                break
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(f"{endian}IIII", packet_header)
            payload = read_exact(process.stdout, incl_len)
            if payload is None:
                break
            timestamp = ts_sec + (ts_frac / divisor)
            record = _parse_packet_record(payload, timestamp, linktype=linktype)
            if record is None:
                continue
            phase = read_phase(phase_path)
            window_start = int(record.timestamp / args.window_size) * args.window_size
            buckets.setdefault(phase_key(phase, window_start), []).append(record)
            flush_ready(window_start)
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        flush_ready(flush_all=True)
        persist_event(args.run_id, "live_capture_stopped", total_rows=total_rows)

    if process.returncode not in (0, -signal.SIGTERM, -signal.SIGINT) and not stop_requested:
        raise LiveCaptureError(f"tcpdump exited with status {process.returncode}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Write live packet feature windows to Redis.")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--iface", required=True)
    parser.add_argument("--target-ip", required=True)
    parser.add_argument("--window-size", type=float, default=1.0)
    parser.add_argument("--phase-file", default="")
    parser.add_argument("--artifact", default="live_features")
    parser.add_argument("--tcpdump", default="tcpdump")
    parser.add_argument("--sudo-command", default="sudo")
    parser.add_argument("--tcpdump-log", default="")
    parser.add_argument("--no-sudo", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.window_size <= 0:
        print("[live][error] --window-size must be positive", file=sys.stderr, flush=True)
        return 1
    if args.no_sudo:
        args.sudo_command = ""
    try:
        return run_live_capture(args)
    except (LiveCaptureError, StorageError, OSError, subprocess.SubprocessError) as exc:
        print(f"[live][error] {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
