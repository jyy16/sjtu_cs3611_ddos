import json

import numpy as np
import pandas as pd
import torch

from models.infer import export_fast_model
from models.infer import run_inference
from models.train_mlp import train_from_csv


def _make_feature_frame() -> pd.DataFrame:
    rng = np.random.default_rng(42)
    rows = []
    for idx in range(50):
        rows.append(
            {
                "timestamp": f"2026-05-22T12:00:{idx % 50:02d}+08:00",
                "src_ip": f"10.0.0.{idx % 8 + 10}",
                "dst_ip": "10.0.0.2",
                "protocol": "TCP",
                "pps": float(rng.normal(5, 1)),
                "bps": float(rng.normal(2500, 200)),
                "avg_pkt_size": float(rng.normal(95, 5)),
                "syn_count": float(rng.integers(0, 2)),
                "ack_count": float(rng.integers(3, 8)),
                "syn_ack_ratio": float(rng.normal(0.15, 0.03)),
                "unique_src_ips": 3,
                "ip_entropy": 1.5,
                "label": "normal",
                "attack_type": "none",
            }
        )
    for idx in range(50):
        rows.append(
            {
                "timestamp": f"2026-05-22T12:01:{idx % 50:02d}+08:00",
                "src_ip": f"10.0.1.{idx % 8 + 20}",
                "dst_ip": "10.0.0.2",
                "protocol": "TCP",
                "pps": float(rng.normal(180, 12)),
                "bps": float(rng.normal(80000, 4000)),
                "avg_pkt_size": float(rng.normal(60, 3)),
                "syn_count": float(rng.normal(170, 8)),
                "ack_count": float(rng.integers(0, 3)),
                "syn_ack_ratio": float(rng.normal(160, 8)),
                "unique_src_ips": 25,
                "ip_entropy": 4.3,
                "label": "attack",
                "attack_type": "syn_flood",
            }
        )
    return pd.DataFrame(rows)


def test_trains_mlp_and_writes_metrics(tmp_path):
    train_csv = tmp_path / "train.csv"
    model_path = tmp_path / "model.pth"
    metrics_path = tmp_path / "metrics.json"
    _make_feature_frame().to_csv(train_csv, index=False)

    metrics = train_from_csv(
        input_path=train_csv,
        output_path=model_path,
        metrics_out=metrics_path,
        epochs=70,
        seed=7,
    )

    assert model_path.exists()
    assert metrics_path.exists()
    assert metrics["accuracy"] >= 0.90
    assert metrics["precision"] >= 0.90
    assert metrics["recall"] >= 0.90
    assert metrics["f1"] >= 0.90


def test_inference_outputs_block_decision_for_attack_source(tmp_path):
    train_csv = tmp_path / "train.csv"
    model_path = tmp_path / "model.pth"
    metrics_path = tmp_path / "metrics.json"
    decision_path = tmp_path / "decision.json"
    _make_feature_frame().to_csv(train_csv, index=False)
    train_from_csv(train_csv, model_path, metrics_path, epochs=70, seed=11)

    infer_frame = pd.DataFrame(
        [
            {
                "timestamp": "2026-05-22T12:10:00+08:00",
                "src_ip": "10.0.1.99",
                "dst_ip": "10.0.0.2",
                "protocol": "TCP",
                "pps": 220.0,
                "bps": 95000.0,
                "avg_pkt_size": 58.0,
                "syn_count": 210.0,
                "ack_count": 0.0,
                "syn_ack_ratio": 210.0,
                "unique_src_ips": 30,
                "ip_entropy": 4.8,
                "label": "attack",
                "attack_type": "mixed_attack",
            }
        ]
    )
    infer_csv = tmp_path / "infer.csv"
    infer_frame.to_csv(infer_csv, index=False)

    result = run_inference(
        input_path=infer_csv,
        model_path=model_path,
        output_path=decision_path,
        threshold=0.80,
    )

    assert decision_path.exists()
    saved = json.loads(decision_path.read_text(encoding="utf-8"))
    assert saved == result
    assert saved["generated_at"].endswith("+08:00")
    assert saved["threshold"] == 0.8
    assert saved["decisions"][0]["src_ip"] == "10.0.1.99"
    assert saved["decisions"][0]["label"] == "attack"
    assert saved["decisions"][0]["action"] == "block"
    assert saved["decisions"][0]["reason"] == "model_detected_mixed_attack"
    assert saved["decisions"][0]["confidence"] >= 0.80


def test_fast_model_export_matches_torch_inference(tmp_path):
    train_csv = tmp_path / "train.csv"
    model_path = tmp_path / "model.pth"
    fast_model_path = tmp_path / "model.fast.json"
    metrics_path = tmp_path / "metrics.json"
    _make_feature_frame().to_csv(train_csv, index=False)
    train_from_csv(train_csv, model_path, metrics_path, epochs=35, seed=13)

    infer_csv = tmp_path / "infer.csv"
    _make_feature_frame().tail(10).to_csv(infer_csv, index=False)
    torch_decision_path = tmp_path / "decision_torch.json"
    fast_decision_path = tmp_path / "decision_fast.json"

    payload = export_fast_model(model_path, fast_model_path)
    torch_result = run_inference(infer_csv, model_path, torch_decision_path, threshold=0.80)
    fast_result = run_inference(infer_csv, fast_model_path, fast_decision_path, threshold=0.80)

    assert payload["format"] == "cs3611-fast-mlp-v1"
    assert fast_model_path.exists()
    assert [item["src_ip"] for item in fast_result["decisions"]] == [
        item["src_ip"] for item in torch_result["decisions"]
    ]
    np.testing.assert_allclose(
        [item["confidence"] for item in fast_result["decisions"]],
        [item["confidence"] for item in torch_result["decisions"]],
        atol=1e-5,
    )


def test_training_writes_checkpoints_history_and_tuned_threshold(tmp_path):
    train_csv = tmp_path / "train.csv"
    model_path = tmp_path / "model.pth"
    metrics_path = tmp_path / "metrics.json"
    checkpoint_dir = tmp_path / "checkpoints"
    _make_feature_frame().to_csv(train_csv, index=False)

    metrics = train_from_csv(
        input_path=train_csv,
        output_path=model_path,
        metrics_out=metrics_path,
        checkpoint_dir=checkpoint_dir,
        checkpoint_every=10,
        epochs=35,
        seed=19,
    )

    assert (checkpoint_dir / "latest.pth").exists()
    assert (checkpoint_dir / "best_model.pth").exists()
    assert (checkpoint_dir / "epoch_010.pth").exists()
    assert metrics["best_epoch"] >= 1
    assert 0.05 <= metrics["best_threshold"] <= 0.95
    assert metrics["roc_auc"] >= 0.95
    assert metrics["confusion_matrix"]["tn"] + metrics["confusion_matrix"]["tp"] > 0
    assert len(metrics["history"]) >= 2
    assert {"epoch", "train_loss", "valid_loss", "accuracy", "f1"}.issubset(metrics["history"][0])

    checkpoint = torch.load(model_path, map_location="cpu", weights_only=False)
    assert checkpoint["decision_threshold"] == metrics["best_threshold"]
    assert checkpoint["best_epoch"] == metrics["best_epoch"]


def test_inference_can_use_saved_decision_threshold(tmp_path):
    train_csv = tmp_path / "train.csv"
    model_path = tmp_path / "model.pth"
    metrics_path = tmp_path / "metrics.json"
    _make_feature_frame().to_csv(train_csv, index=False)
    metrics = train_from_csv(train_csv, model_path, metrics_path, epochs=35, seed=23)

    infer_csv = tmp_path / "infer.csv"
    _make_feature_frame().tail(5).to_csv(infer_csv, index=False)
    decision_path = tmp_path / "decision.json"

    result = run_inference(
        input_path=infer_csv,
        model_path=model_path,
        output_path=decision_path,
        threshold=None,
    )

    assert result["threshold"] == metrics["best_threshold"]


def test_inference_skips_public_sources_that_defense_refuses(tmp_path):
    train_csv = tmp_path / "train.csv"
    model_path = tmp_path / "model.pth"
    metrics_path = tmp_path / "metrics.json"
    _make_feature_frame().to_csv(train_csv, index=False)
    train_from_csv(train_csv, model_path, metrics_path, epochs=35, seed=31)

    infer_frame = pd.DataFrame(
        [
            {
                "timestamp": "2026-05-22T12:10:00+08:00",
                "src_ip": "8.8.8.8",
                "dst_ip": "127.0.0.1",
                "protocol": "TCP",
                "pps": 220.0,
                "bps": 95000.0,
                "avg_pkt_size": 58.0,
                "syn_count": 210.0,
                "ack_count": 0.0,
                "syn_ack_ratio": 210.0,
                "unique_src_ips": 30,
                "ip_entropy": 4.8,
                "label": "attack",
                "attack_type": "mixed_attack",
            },
            {
                "timestamp": "2026-05-22T12:10:01+08:00",
                "src_ip": "10.0.0.9",
                "dst_ip": "127.0.0.1",
                "protocol": "TCP",
                "pps": 230.0,
                "bps": 99000.0,
                "avg_pkt_size": 58.0,
                "syn_count": 220.0,
                "ack_count": 0.0,
                "syn_ack_ratio": 220.0,
                "unique_src_ips": 30,
                "ip_entropy": 4.8,
                "label": "attack",
                "attack_type": "mixed_attack",
            },
        ]
    )
    infer_csv = tmp_path / "infer.csv"
    infer_frame.to_csv(infer_csv, index=False)
    decision_path = tmp_path / "decision.json"

    result = run_inference(infer_csv, model_path, decision_path, threshold=0.80)

    assert [decision["src_ip"] for decision in result["decisions"]] == ["10.0.0.9"]
