"""Extract Project 9 traffic statistics from PCAP/PCAPNG captures."""

from __future__ import annotations

import argparse
import math
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

import pandas as pd

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from storage.redis_store import StorageError, persist_feature_frame


FEATURE_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "protocol",
    "pps",
    "bps",
    "avg_pkt_size",
    "syn_count",
    "ack_count",
    "syn_ack_ratio",
    "unique_src_ips",
    "ip_entropy",
    "label",
    "attack_type",
]

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_IP = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276


@dataclass(frozen=True)
class PacketRecord:
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    length: int
    syn: bool = False
    ack: bool = False


def _ip_to_text(raw: bytes) -> str:
    return ".".join(str(part) for part in raw)


def _shannon_entropy(values: Iterable[str]) -> float:
    counts = Counter(values)
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return float(-sum((count / total) * math.log2(count / total) for count in counts.values()))


def _parse_ipv4_at_offset(payload: bytes, timestamp: float, offset: int) -> PacketRecord | None:
    if len(payload) < offset + 20:
        return None

    version_ihl = payload[offset]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or ihl < 20 or len(payload) < offset + ihl:
        return None

    protocol_number = payload[offset + 9]
    src_ip = _ip_to_text(payload[offset + 12 : offset + 16])
    dst_ip = _ip_to_text(payload[offset + 16 : offset + 20])
    protocol = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol_number, "OTHER")
    transport_offset = offset + ihl
    syn = False
    ack = False

    if protocol_number == 6 and len(payload) >= transport_offset + 14:
        flags = payload[transport_offset + 13]
        syn = bool(flags & 0x02)
        ack = bool(flags & 0x10)

    return PacketRecord(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        length=len(payload),
        syn=syn,
        ack=ack,
    )


def _parse_packet_record(payload: bytes, timestamp: float, linktype: int = LINKTYPE_ETHERNET) -> PacketRecord | None:
    if linktype == LINKTYPE_ETHERNET:
        if len(payload) < 14:
            return None
        offset = 14
        ethertype = struct.unpack("!H", payload[12:14])[0]
        if ethertype in {0x8100, 0x88A8}:
            if len(payload) < 18:
                return None
            ethertype = struct.unpack("!H", payload[16:18])[0]
            offset = 18
        if ethertype != 0x0800:
            return None
        return _parse_ipv4_at_offset(payload, timestamp, offset)

    if linktype == LINKTYPE_LINUX_SLL:
        if len(payload) < 16:
            return None
        protocol = struct.unpack("!H", payload[14:16])[0]
        if protocol != 0x0800:
            return None
        return _parse_ipv4_at_offset(payload, timestamp, 16)

    if linktype == LINKTYPE_LINUX_SLL2:
        if len(payload) < 20:
            return None
        protocol = struct.unpack("!H", payload[0:2])[0]
        if protocol != 0x0800:
            return None
        return _parse_ipv4_at_offset(payload, timestamp, 20)

    if linktype == LINKTYPE_RAW_IP:
        return _parse_ipv4_at_offset(payload, timestamp, 0)

    return None


def _read_pcap(path: Path) -> Iterator[tuple[float, bytes, int]]:
    with path.open("rb") as handle:
        magic = handle.read(4)
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
            raise ValueError(f"{path} is not a classic PCAP file")

        header = handle.read(20)
        if len(header) != 20:
            raise ValueError(f"{path} has a truncated PCAP global header")
        *_, linktype = struct.unpack(f"{endian}HHIIII", header)

        while True:
            packet_header = handle.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                raise ValueError(f"{path} has a truncated packet header")
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(f"{endian}IIII", packet_header)
            packet = handle.read(incl_len)
            if len(packet) != incl_len:
                raise ValueError(f"{path} has a truncated packet body")
            yield ts_sec + (ts_frac / divisor), packet, linktype


def _read_pcapng(path: Path) -> Iterator[tuple[float, bytes, int]]:
    endian = "<"
    linktypes: dict[int, int] = {}
    with path.open("rb") as handle:
        while True:
            first = handle.read(12)
            if not first:
                break
            if len(first) != 12:
                raise ValueError(f"{path} has a truncated PCAPNG block header")

            block_type_raw = first[:4]
            if block_type_raw == b"\x0a\x0d\x0d\x0a":
                bom = first[8:12]
                if bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    raise ValueError(f"{path} has an invalid PCAPNG byte-order magic")
                block_type = 0x0A0D0D0A
                block_len = struct.unpack(f"{endian}I", first[4:8])[0]
            else:
                block_type, block_len = struct.unpack(f"{endian}II", first[:8])

            if block_len < 12:
                raise ValueError(f"{path} has an invalid PCAPNG block length")
            rest = handle.read(block_len - 12)
            if len(rest) != block_len - 12:
                raise ValueError(f"{path} has a truncated PCAPNG block")
            body = (first + rest)[8:-4]

            if block_type == 1 and len(body) >= 8:
                interface_id = len(linktypes)
                linktypes[interface_id] = struct.unpack(f"{endian}H", body[:2])[0]
            elif block_type == 6 and len(body) >= 20:
                interface_id, ts_high, ts_low, captured_len, _packet_len = struct.unpack(
                    f"{endian}IIIII", body[:20]
                )
                packet = body[20 : 20 + captured_len]
                timestamp = (((ts_high << 32) | ts_low) / 1_000_000)
                yield timestamp, packet, linktypes.get(interface_id, 1)


def read_packet_records(path: str | Path) -> list[PacketRecord]:
    capture_path = Path(path)
    with capture_path.open("rb") as handle:
        prefix = handle.read(4)

    if prefix == b"\x0a\x0d\x0d\x0a":
        raw_packets = _read_pcapng(capture_path)
    else:
        raw_packets = _read_pcap(capture_path)

    records: list[PacketRecord] = []
    for timestamp, payload, linktype in raw_packets:
        record = _parse_packet_record(payload, timestamp, linktype=linktype)
        if record is not None:
            records.append(record)
    return records


def records_to_feature_frame(
    records: Iterable[PacketRecord],
    label: str,
    attack_type: str,
    target_ip: str | None = None,
    window_size: float = 1.0,
) -> pd.DataFrame:
    if window_size <= 0:
        raise ValueError("window_size must be positive")

    filtered = [record for record in records if target_ip is None or record.dst_ip == target_ip]
    groups: dict[tuple[float, str, str, str], list[PacketRecord]] = defaultdict(list)
    context: dict[tuple[float, str, str], list[str]] = defaultdict(list)

    for record in filtered:
        window_start = math.floor(record.timestamp / window_size) * window_size
        groups[(window_start, record.src_ip, record.dst_ip, record.protocol)].append(record)
        context[(window_start, record.dst_ip, record.protocol)].append(record.src_ip)

    rows = []
    for (window_start, src_ip, dst_ip, protocol), packets in sorted(groups.items()):
        packet_count = len(packets)
        byte_count = sum(packet.length for packet in packets)
        syn_count = sum(1 for packet in packets if packet.syn)
        ack_count = sum(1 for packet in packets if packet.ack)
        context_sources = context[(window_start, dst_ip, protocol)]
        timestamp = datetime.fromtimestamp(window_start, tz=timezone.utc).isoformat()
        rows.append(
            {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "pps": packet_count / window_size,
                "bps": (byte_count * 8) / window_size,
                "avg_pkt_size": byte_count / packet_count if packet_count else 0.0,
                "syn_count": syn_count,
                "ack_count": ack_count,
                "syn_ack_ratio": syn_count / ack_count if ack_count else float(syn_count),
                "unique_src_ips": len(set(context_sources)),
                "ip_entropy": _shannon_entropy(context_sources),
                "label": label,
                "attack_type": attack_type,
            }
        )

    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)


def extract_pcap_to_csv(
    input_path: str | Path,
    output_path: str | Path,
    label: str,
    attack_type: str = "none",
    target_ip: str | None = None,
    window_size: float = 1.0,
) -> pd.DataFrame:
    records = read_packet_records(input_path)
    frame = records_to_feature_frame(
        records=records,
        label=label,
        attack_type=attack_type,
        target_ip=target_ip,
        window_size=window_size,
    )
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output, index=False)
    storage_info = persist_feature_frame(
        frame,
        output_path=output,
        input_path=input_path,
        label=label,
        attack_type=attack_type,
        target_ip=target_ip,
        window_size=window_size,
    )
    if storage_info is not None:
        frame.attrs["storage"] = storage_info
    return frame


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Extract statistical DDoS features from PCAP/PCAPNG.")
    parser.add_argument("--input", required=True, help="Input .pcap or .pcapng file.")
    parser.add_argument("--output", required=True, help="Output feature CSV path.")
    parser.add_argument("--label", required=True, choices=["normal", "attack"], help="Label assigned to rows.")
    parser.add_argument("--attack-type", default="none", help="Attack type name, e.g. syn_flood.")
    parser.add_argument("--target-ip", default=None, help="Victim IP. When set, only inbound packets are used.")
    parser.add_argument("--window-size", type=float, default=1.0, help="Aggregation window in seconds.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        frame = extract_pcap_to_csv(
            input_path=args.input,
            output_path=args.output,
            label=args.label,
            attack_type=args.attack_type,
            target_ip=args.target_ip,
            window_size=args.window_size,
        )
    except StorageError as exc:
        print(f"[storage][error] {exc}", flush=True)
        return 1
    print(f"Wrote {len(frame)} feature rows to {args.output}")
    storage_info = frame.attrs.get("storage")
    if storage_info:
        print(
            "Stored feature rows in Redis: "
            f"run={storage_info['run_id']} artifact={storage_info['artifact']} key={storage_info['key']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
