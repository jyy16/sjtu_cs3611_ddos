"""Unsupervised KMeans anomaly detection for Project 9 traffic features."""

from __future__ import annotations

import argparse
import json
import os
import pickle
import sys
from pathlib import Path
from typing import Any

os.environ.setdefault("OMP_NUM_THREADS", "1")

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from models.feature_utils import NUMERIC_FEATURES, feature_matrix, load_feature_csv


RISK_FEATURES = ["pps", "bps", "syn_count", "syn_ack_ratio", "unique_src_ips", "ip_entropy"]


def _majority_cluster_purity(labels: np.ndarray, truth: pd.Series) -> float | None:
    if truth.empty:
        return None
    total = 0
    majority = 0
    for cluster in sorted(set(labels.tolist())):
        members = truth.iloc[np.where(labels == cluster)[0]].astype(str).str.lower()
        if members.empty:
            continue
        counts = members.value_counts()
        majority += int(counts.iloc[0])
        total += int(counts.sum())
    return float(majority / total) if total else None


def _binary_metric_counts(predicted_anomaly: np.ndarray, truth: pd.Series) -> tuple[float | None, float | None]:
    if truth.empty:
        return None, None
    actual_attack = truth.astype(str).str.lower().eq("attack").to_numpy()
    true_positive = int(np.logical_and(predicted_anomaly, actual_attack).sum())
    false_positive = int(np.logical_and(predicted_anomaly, ~actual_attack).sum())
    false_negative = int(np.logical_and(~predicted_anomaly, actual_attack).sum())
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    return float(precision), float(recall)


def _select_anomaly_cluster(frame: pd.DataFrame, labels: np.ndarray) -> int:
    risk_frame = frame.reindex(columns=RISK_FEATURES, fill_value=0).apply(pd.to_numeric, errors="coerce")
    risk_frame = risk_frame.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    means = risk_frame.groupby(labels).mean()
    baseline = risk_frame.mean()
    spread = risk_frame.std(ddof=0).replace(0, 1.0)
    normalized = (means - baseline) / spread
    risk_scores = normalized.mean(axis=1)
    return int(risk_scores.idxmax())


def fit_kmeans_anomaly(
    input_path: str | Path,
    output_path: str | Path,
    model_out: str | Path,
    clusters: int = 2,
    seed: int = 42,
) -> dict[str, Any]:
    if clusters < 2:
        raise ValueError("clusters must be at least 2")

    frame = load_feature_csv(input_path)
    x_raw = feature_matrix(frame, NUMERIC_FEATURES)
    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(x_raw)
    kmeans = KMeans(n_clusters=clusters, random_state=seed, n_init=20)
    labels = kmeans.fit_predict(x_scaled)
    anomaly_cluster = _select_anomaly_cluster(frame, labels)
    predicted_anomaly = labels == anomaly_cluster

    truth = frame["label"] if "label" in frame.columns else pd.Series(dtype=str)
    purity = _majority_cluster_purity(labels, truth)
    precision, recall = _binary_metric_counts(predicted_anomaly, truth)
    silhouette = float(silhouette_score(x_scaled, labels)) if len(set(labels.tolist())) > 1 else 0.0

    assignments = []
    for idx, row in frame.iterrows():
        assignments.append(
            {
                "row": int(idx),
                "src_ip": str(row.get("src_ip", "")),
                "cluster": int(labels[idx]),
                "is_anomaly": bool(predicted_anomaly[idx]),
                "pps": float(row.get("pps", 0.0)),
                "syn_ack_ratio": float(row.get("syn_ack_ratio", 0.0)),
            }
        )

    cluster_summary = []
    for cluster in sorted(set(labels.tolist())):
        members = frame.iloc[np.where(labels == cluster)[0]]
        cluster_summary.append(
            {
                "cluster": int(cluster),
                "rows": int(len(members)),
                "mean_pps": float(pd.to_numeric(members["pps"], errors="coerce").fillna(0).mean()),
                "mean_syn_ack_ratio": float(
                    pd.to_numeric(members["syn_ack_ratio"], errors="coerce").fillna(0).mean()
                ),
                "is_anomaly_cluster": bool(cluster == anomaly_cluster),
            }
        )

    report = {
        "clusters": int(clusters),
        "anomaly_cluster": int(anomaly_cluster),
        "silhouette": silhouette,
        "cluster_purity": purity,
        "anomaly_precision": precision,
        "anomaly_recall": recall,
        "cluster_summary": cluster_summary,
        "assignments": assignments,
    }

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")

    model_path = Path(model_out)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    with model_path.open("wb") as handle:
        pickle.dump(
            {
                "kmeans": kmeans,
                "scaler": scaler,
                "feature_columns": NUMERIC_FEATURES,
                "anomaly_cluster": anomaly_cluster,
            },
            handle,
        )

    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run KMeans anomaly detection on traffic features.")
    parser.add_argument("--input", required=True, help="Input feature CSV.")
    parser.add_argument("--output", required=True, help="Output anomaly report JSON.")
    parser.add_argument("--model-out", required=True, help="Output KMeans model pickle.")
    parser.add_argument("--clusters", type=int, default=2, help="Number of KMeans clusters.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = fit_kmeans_anomaly(
        input_path=args.input,
        output_path=args.output,
        model_out=args.model_out,
        clusters=args.clusters,
        seed=args.seed,
    )
    compact = {key: value for key, value in report.items() if key != "assignments"}
    print(json.dumps(compact, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
