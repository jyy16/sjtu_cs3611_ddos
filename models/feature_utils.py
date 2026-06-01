"""Shared feature loading and preprocessing helpers."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler


NUMERIC_FEATURES = [
    "pps",
    "bps",
    "avg_pkt_size",
    "syn_count",
    "ack_count",
    "syn_ack_ratio",
    "unique_src_ips",
    "ip_entropy",
]

LABEL_TO_ID = {"normal": 0, "attack": 1}
ID_TO_LABEL = {value: key for key, value in LABEL_TO_ID.items()}


def load_feature_csv(path: str | Path) -> pd.DataFrame:
    frame = pd.read_csv(path)
    missing = [column for column in NUMERIC_FEATURES if column not in frame.columns]
    if missing:
        raise ValueError(f"feature CSV is missing required columns: {', '.join(missing)}")
    return frame


def feature_matrix(frame: pd.DataFrame, feature_columns: list[str] | None = None) -> np.ndarray:
    columns = feature_columns or NUMERIC_FEATURES
    matrix = frame.reindex(columns=columns, fill_value=0).apply(pd.to_numeric, errors="coerce")
    matrix = matrix.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return matrix.to_numpy(dtype=np.float32)


def labels_from_frame(frame: pd.DataFrame) -> np.ndarray:
    if "label" not in frame.columns:
        raise ValueError("feature CSV must include a label column for supervised training")
    labels = frame["label"].astype(str).str.lower().map(LABEL_TO_ID)
    if labels.isna().any():
        bad_values = sorted(set(frame.loc[labels.isna(), "label"].astype(str)))
        raise ValueError(f"unsupported labels: {bad_values}; expected normal or attack")
    return labels.to_numpy(dtype=np.float32)


def scaler_to_state(scaler: StandardScaler) -> dict[str, list[float]]:
    return {
        "mean": scaler.mean_.astype(float).tolist(),
        "scale": scaler.scale_.astype(float).tolist(),
        "var": scaler.var_.astype(float).tolist(),
    }


def scaler_from_state(state: dict[str, list[float]]) -> StandardScaler:
    scaler = StandardScaler()
    scaler.mean_ = np.asarray(state["mean"], dtype=np.float64)
    scaler.scale_ = np.asarray(state["scale"], dtype=np.float64)
    scaler.var_ = np.asarray(state.get("var", np.square(scaler.scale_)), dtype=np.float64)
    scaler.n_features_in_ = len(scaler.mean_)
    return scaler


def source_attack_type(group: pd.DataFrame) -> str:
    if "attack_type" not in group.columns:
        return "unknown"
    values = [value for value in group["attack_type"].astype(str) if value and value != "nan"]
    if not values:
        return "unknown"
    non_none = [value for value in values if value.lower() != "none"]
    return non_none[0] if non_none else values[0]
