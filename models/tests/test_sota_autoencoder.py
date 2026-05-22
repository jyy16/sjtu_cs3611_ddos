import json

import numpy as np
import pandas as pd
import torch

from models.anomaly_autoencoder import train_autoencoder_anomaly
from models.sota_fusion import run_sota_fusion


def _make_sota_frame() -> pd.DataFrame:
    rng = np.random.default_rng(2026)
    rows = []
    for idx in range(60):
        rows.append(
            {
                "timestamp": f"2026-05-22T14:00:{idx % 60:02d}+08:00",
                "src_ip": f"10.0.0.{10 + idx % 12}",
                "dst_ip": "10.0.0.2",
                "protocol": "TCP",
                "pps": float(rng.normal(6, 0.8)),
                "bps": float(rng.normal(2600, 180)),
                "avg_pkt_size": float(rng.normal(96, 5)),
                "syn_count": float(rng.integers(0, 2)),
                "ack_count": float(rng.integers(3, 8)),
                "syn_ack_ratio": float(rng.normal(0.18, 0.03)),
                "unique_src_ips": 4,
                "ip_entropy": 1.7,
                "label": "normal",
                "attack_type": "none",
            }
        )
    for idx in range(60):
        rows.append(
            {
                "timestamp": f"2026-05-22T14:01:{idx % 60:02d}+08:00",
                "src_ip": f"10.0.1.{30 + idx % 12}",
                "dst_ip": "10.0.0.2",
                "protocol": "TCP",
                "pps": float(rng.normal(210, 16)),
                "bps": float(rng.normal(98000, 4500)),
                "avg_pkt_size": float(rng.normal(58, 4)),
                "syn_count": float(rng.normal(200, 10)),
                "ack_count": float(rng.integers(0, 2)),
                "syn_ack_ratio": float(rng.normal(190, 10)),
                "unique_src_ips": 34,
                "ip_entropy": 4.7,
                "label": "attack",
                "attack_type": "unknown_high_rate",
            }
        )
    return pd.DataFrame(rows)


def test_autoencoder_detects_attack_by_reconstruction_error(tmp_path):
    feature_csv = tmp_path / "features.csv"
    report_path = tmp_path / "ae_report.json"
    model_path = tmp_path / "autoencoder.pth"
    checkpoint_dir = tmp_path / "ae_checkpoints"
    _make_sota_frame().to_csv(feature_csv, index=False)

    report = train_autoencoder_anomaly(
        input_path=feature_csv,
        output_path=report_path,
        model_out=model_path,
        checkpoint_dir=checkpoint_dir,
        epochs=45,
        seed=5,
    )

    assert model_path.exists()
    assert report_path.exists()
    assert (checkpoint_dir / "best_model.pth").exists()
    assert (checkpoint_dir / "latest.pth").exists()
    assert report["anomaly_precision"] >= 0.95
    assert report["anomaly_recall"] >= 0.95
    assert report["roc_auc"] >= 0.95
    assert report["threshold"] > 0
    assert len(report["history"]) >= 2
    assert len(report["assignments"]) == 120

    checkpoint = torch.load(model_path, map_location="cpu", weights_only=False)
    assert checkpoint["threshold"] == report["threshold"]
    assert checkpoint["best_epoch"] == report["best_epoch"]


def test_sota_fusion_report_combines_all_detectors(tmp_path):
    feature_csv = tmp_path / "features.csv"
    output_path = tmp_path / "sota_report.json"
    model_dir = tmp_path / "sota_models"
    _make_sota_frame().to_csv(feature_csv, index=False)

    report = run_sota_fusion(
        input_path=feature_csv,
        output_path=output_path,
        model_dir=model_dir,
        epochs=40,
        seed=13,
    )

    saved = json.loads(output_path.read_text(encoding="utf-8"))
    assert saved == report
    assert (model_dir / "mlp_model.pth").exists()
    assert (model_dir / "autoencoder.pth").exists()
    assert (model_dir / "kmeans.pkl").exists()
    assert report["overall"]["fusion_f1"] >= 0.95
    assert report["overall"]["fusion_precision"] >= 0.95
    assert report["overall"]["fusion_recall"] >= 0.95
    assert {"mlp", "autoencoder", "kmeans"}.issubset(report["components"])
    assert len(report["decisions"]) > 0
    assert report["decisions"][0]["action"] == "block"
