"""SOTA-inspired fused detector for Project 9 traffic features.

This module combines the supervised MLP, AutoEncoder reconstruction error, and
KMeans cluster anomaly signal into a single report. It is intentionally compact:
the goal is a robust course-demo pipeline, not a heavyweight research system.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

os.environ.setdefault("OMP_NUM_THREADS", "1")

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from models.anomaly_autoencoder import train_autoencoder_anomaly
from models.anomaly_kmeans import fit_kmeans_anomaly
from models.feature_utils import load_feature_csv, source_attack_type
from models.infer import predict_probabilities
from models.train_mlp import train_from_csv


def _truth(frame: pd.DataFrame) -> np.ndarray | None:
    if "label" not in frame.columns:
        return None
    labels = frame["label"].astype(str).str.lower().map({"normal": 0, "attack": 1})
    if labels.isna().any():
        return None
    return labels.to_numpy(dtype=int)


def _binary_metrics(labels: np.ndarray | None, scores: np.ndarray, threshold: float) -> dict[str, float | None]:
    if labels is None:
        return {
            "fusion_accuracy": None,
            "fusion_precision": None,
            "fusion_recall": None,
            "fusion_f1": None,
            "fusion_roc_auc": None,
        }
    predicted = scores >= threshold
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels,
        predicted.astype(int),
        average="binary",
        zero_division=0,
    )
    try:
        roc_auc = float(roc_auc_score(labels, scores))
    except ValueError:
        roc_auc = 0.0
    return {
        "fusion_accuracy": float(accuracy_score(labels, predicted.astype(int))),
        "fusion_precision": float(precision),
        "fusion_recall": float(recall),
        "fusion_f1": float(f1),
        "fusion_roc_auc": roc_auc,
    }


def _best_threshold(labels: np.ndarray | None, scores: np.ndarray) -> float:
    if labels is None:
        return 0.5
    best_threshold = 0.5
    best_f1 = -1.0
    for threshold in np.linspace(0.05, 0.95, 91):
        metrics = _binary_metrics(labels, scores, float(threshold))
        f1 = float(metrics["fusion_f1"] or 0.0)
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = float(round(float(threshold), 2))
    return best_threshold


def _score_autoencoder(assignments: list[dict[str, Any]], threshold: float) -> np.ndarray:
    errors = np.asarray([float(item["reconstruction_error"]) for item in assignments], dtype=np.float32)
    denominator = max(float(threshold) * 2.0, 1e-8)
    return np.clip(errors / denominator, 0.0, 1.0)


def _score_kmeans(assignments: list[dict[str, Any]]) -> np.ndarray:
    return np.asarray([1.0 if item["is_anomaly"] else 0.0 for item in assignments], dtype=np.float32)


def run_sota_fusion(
    input_path: str | Path,
    output_path: str | Path,
    model_dir: str | Path,
    epochs: int = 80,
    contamination: float = 0.05,
    seed: int = 42,
) -> dict[str, Any]:
    frame = load_feature_csv(input_path)
    labels = _truth(frame)
    model_root = Path(model_dir)
    model_root.mkdir(parents=True, exist_ok=True)

    mlp_model = model_root / "mlp_model.pth"
    mlp_metrics = model_root / "mlp_metrics.json"
    mlp_checkpoint_dir = model_root / "mlp_checkpoints"
    mlp_report = train_from_csv(
        input_path=input_path,
        output_path=mlp_model,
        metrics_out=mlp_metrics,
        epochs=epochs,
        checkpoint_dir=mlp_checkpoint_dir,
        checkpoint_every=max(1, epochs // 4),
        seed=seed,
    )
    mlp_scores, _mlp_frame, _checkpoint = predict_probabilities(input_path, mlp_model)

    ae_model = model_root / "autoencoder.pth"
    ae_report_path = model_root / "autoencoder_report.json"
    ae_checkpoint_dir = model_root / "autoencoder_checkpoints"
    ae_report = train_autoencoder_anomaly(
        input_path=input_path,
        output_path=ae_report_path,
        model_out=ae_model,
        checkpoint_dir=ae_checkpoint_dir,
        epochs=epochs,
        contamination=contamination,
        seed=seed + 1,
    )
    ae_scores = _score_autoencoder(ae_report["assignments"], float(ae_report["threshold"]))

    kmeans_model = model_root / "kmeans.pkl"
    kmeans_report_path = model_root / "kmeans_report.json"
    kmeans_report = fit_kmeans_anomaly(
        input_path=input_path,
        output_path=kmeans_report_path,
        model_out=kmeans_model,
        clusters=2,
        seed=seed + 2,
    )
    kmeans_scores = _score_kmeans(kmeans_report["assignments"])

    fusion_scores = np.mean(np.vstack([mlp_scores, ae_scores, kmeans_scores]), axis=0)
    threshold = _best_threshold(labels, fusion_scores)
    overall = {
        "fusion_threshold": threshold,
        **_binary_metrics(labels, fusion_scores, threshold),
    }

    working = frame.copy()
    working["_fusion_score"] = fusion_scores
    decisions = []
    for src_ip, group in working.groupby("src_ip", sort=True):
        confidence = float(group["_fusion_score"].max())
        if confidence < threshold:
            continue
        attack_type = source_attack_type(group)
        decisions.append(
            {
                "src_ip": str(src_ip),
                "label": "attack",
                "attack_type": attack_type,
                "confidence": round(confidence, 6),
                "action": "block",
                "reason": f"sota_fusion_detected_{attack_type}",
            }
        )

    report = {
        "model": "sota_fusion_mlp_autoencoder_kmeans",
        "input": str(input_path),
        "overall": overall,
        "components": {
            "mlp": {
                "accuracy": mlp_report["accuracy"],
                "precision": mlp_report["precision"],
                "recall": mlp_report["recall"],
                "f1": mlp_report["f1"],
                "roc_auc": mlp_report["roc_auc"],
                "best_threshold": mlp_report["best_threshold"],
            },
            "autoencoder": {
                "precision": ae_report["anomaly_precision"],
                "recall": ae_report["anomaly_recall"],
                "f1": ae_report["anomaly_f1"],
                "roc_auc": ae_report["roc_auc"],
                "threshold": ae_report["threshold"],
            },
            "kmeans": {
                "precision": kmeans_report["anomaly_precision"],
                "recall": kmeans_report["anomaly_recall"],
                "cluster_purity": kmeans_report["cluster_purity"],
                "silhouette": kmeans_report["silhouette"],
            },
        },
        "decisions": decisions,
    }

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train and evaluate the Project 9 SOTA-inspired fusion detector.")
    parser.add_argument("--input", required=True, help="Input feature CSV.")
    parser.add_argument("--output", required=True, help="Output fusion report JSON.")
    parser.add_argument("--model-dir", required=True, help="Directory for component models and reports.")
    parser.add_argument("--epochs", type=int, default=80, help="Training epochs for neural components.")
    parser.add_argument("--contamination", type=float, default=0.05, help="Expected anomaly fraction for AutoEncoder.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = run_sota_fusion(
        input_path=args.input,
        output_path=args.output,
        model_dir=args.model_dir,
        epochs=args.epochs,
        contamination=args.contamination,
        seed=args.seed,
    )
    compact = {key: value for key, value in report.items() if key != "decisions"}
    print(json.dumps(compact, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
