import struct

import pandas as pd

from features.extract_features import FEATURE_COLUMNS, extract_pcap_to_csv


def _ip_bytes(ip: str) -> bytes:
    return bytes(int(part) for part in ip.split("."))


def _tcp_packet(src_ip: str, dst_ip: str, flags: int, payload: bytes = b"") -> bytes:
    eth = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + struct.pack("!H", 0x0800)
    tcp_len = 20 + len(payload)
    total_len = 20 + tcp_len
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        1,
        0,
        64,
        6,
        0,
        _ip_bytes(src_ip),
        _ip_bytes(dst_ip),
    )
    tcp_header = struct.pack("!HHIIBBHHH", 12345, 80, 0, 0, 5 << 4, flags, 8192, 0, 0)
    return eth + ip_header + tcp_header + payload


def _write_pcap(path, packets):
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, payload in packets:
            ts_sec = int(timestamp)
            ts_usec = int((timestamp - ts_sec) * 1_000_000)
            handle.write(struct.pack("<IIII", ts_sec, ts_usec, len(payload), len(payload)))
            handle.write(payload)


def test_extracts_windowed_ddos_features_from_pcap(tmp_path):
    pcap_path = tmp_path / "mixed.pcap"
    csv_path = tmp_path / "features.csv"
    packets = []

    for idx in range(4):
        packets.append((1.05 + idx * 0.05, _tcp_packet("10.0.0.3", "10.0.0.2", 0x10)))

    for idx in range(30):
        packets.append((2.01 + idx * 0.01, _tcp_packet("10.0.0.9", "10.0.0.2", 0x02)))

    _write_pcap(pcap_path, packets)

    frame = extract_pcap_to_csv(
        input_path=pcap_path,
        output_path=csv_path,
        label="attack",
        attack_type="syn_flood",
        target_ip="10.0.0.2",
        window_size=1.0,
    )

    assert csv_path.exists()
    assert list(frame.columns) == FEATURE_COLUMNS

    saved = pd.read_csv(csv_path)
    attack_row = saved[saved["src_ip"] == "10.0.0.9"].iloc[0]
    normal_like_row = saved[saved["src_ip"] == "10.0.0.3"].iloc[0]

    assert attack_row["pps"] == 30
    assert attack_row["syn_count"] == 30
    assert attack_row["ack_count"] == 0
    assert attack_row["syn_ack_ratio"] == 30
    assert attack_row["avg_pkt_size"] > 40
    assert normal_like_row["pps"] == 4
    assert normal_like_row["syn_ack_ratio"] == 0
    assert set(saved["label"]) == {"attack"}
    assert set(saved["attack_type"]) == {"syn_flood"}
