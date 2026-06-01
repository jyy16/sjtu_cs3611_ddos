# Traffic Feature Schema

`features/extract_features.py` writes one CSV row per source IP, destination IP,
protocol, and time window. When `--target-ip` is supplied, only inbound packets
whose destination is the target are included so the downstream decision can
attribute suspicious traffic to the real source.

| Column | Type | Meaning |
| --- | --- | --- |
| `timestamp` | ISO-8601 string | Start time of the aggregation window. |
| `src_ip` | string | Source IP for this row. |
| `dst_ip` | string | Destination IP, normally the protected host. |
| `protocol` | string | `TCP`, `UDP`, `ICMP`, or `OTHER`. |
| `pps` | float | Packets per second in the window. |
| `bps` | float | Bits per second in the window. |
| `avg_pkt_size` | float | Average captured packet size in bytes. |
| `syn_count` | integer | Count of TCP packets with the SYN flag set. |
| `ack_count` | integer | Count of TCP packets with the ACK flag set. |
| `syn_ack_ratio` | float | `syn_count / ack_count`; if ACK is zero, uses `syn_count`. |
| `unique_src_ips` | integer | Number of distinct source IPs seen for the same destination/protocol/window. |
| `ip_entropy` | float | Shannon entropy of source IP distribution in the same destination/protocol/window. |
| `label` | string | `normal` or `attack`, supplied by the caller for training data. |
| `attack_type` | string | `none`, `syn_flood`, `http_flood`, `udp_reflection`, `mixed_attack`, etc. |

Example:

```bash
python features/extract_features.py \
  --input data/pcap/demo/attack_before_defense.pcap \
  --output data/features/demo/attack_before_defense.csv \
  --label attack \
  --attack-type mixed_attack \
  --target-ip 127.0.0.1 \
  --window-size 1
```
