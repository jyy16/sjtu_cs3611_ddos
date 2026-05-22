import numpy as np
import pandas as pd

from models.anomaly_kmeans import fit_kmeans_anomaly


def test_kmeans_separates_high_rate_attack_from_background(tmp_path):
    rng = np.random.default_rng(123)
    rows = []
    for idx in range(40):
        rows.append(
            {
                "timestamp": f"2026-05-22T13:00:{idx % 40:02d}+08:00",
                "src_ip": f"10.0.0.{idx % 10 + 10}",
                "dst_ip": "10.0.0.2",
                "protocol": "TCP",
                "pps": float(rng.normal(7, 1)),
                "bps": float(rng.normal(2800, 300)),
                "avg_pkt_size": float(rng.normal(100, 4)),
                "syn_count": float(rng.integers(0, 2)),
                "ack_count": float(rng.integers(3, 8)),
                "syn_ack_ratio": float(rng.normal(0.2, 0.04)),
                "unique_src_ips": 4,
                "ip_entropy": 1.8,
                "label": "normal",
                "attack_type": "none",
            }
        )
    for idx in range(40):
        rows.append(
            {
                "timestamp": f"2026-05-22T13:01:{idx % 40:02d}+08:00",
                "src_ip": f"10.0.1.{idx % 10 + 30}",
                "dst_ip": "10.0.0.2",
                "protocol": "TCP",
                "pps": float(rng.normal(190, 15)),
                "bps": float(rng.normal(85000, 3500)),
                "avg_pkt_size": float(rng.normal(62, 3)),
                "syn_count": float(rng.normal(180, 10)),
                "ack_count": float(rng.integers(0, 2)),
                "syn_ack_ratio": float(rng.normal(170, 9)),
                "unique_src_ips": 28,
                "ip_entropy": 4.5,
                "label": "attack",
                "attack_type": "unknown_high_rate",
            }
        )

    feature_csv = tmp_path / "mixed.csv"
    report_path = tmp_path / "anomaly_report.json"
    model_path = tmp_path / "kmeans.pkl"
    pd.DataFrame(rows).to_csv(feature_csv, index=False)

    report = fit_kmeans_anomaly(
        input_path=feature_csv,
        output_path=report_path,
        model_out=model_path,
        clusters=2,
        seed=9,
    )

    assert report_path.exists()
    assert model_path.exists()
    assert report["cluster_purity"] >= 0.95
    assert report["anomaly_precision"] >= 0.95
    assert report["anomaly_recall"] >= 0.95
    assert len(report["assignments"]) == 80
