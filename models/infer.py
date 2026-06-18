"""Run MLP inference and emit defense decisions."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np

if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from models.feature_utils import feature_matrix, load_feature_csv, source_attack_type
from storage.redis_store import StorageError, persist_decision_report

PROJECT_TIMEZONE = timezone(timedelta(hours=8))
FAST_MODEL_FORMAT = "cs3611-fast-mlp-v1"


def _is_defense_actionable_source(src_ip: str) -> bool:
    parts = src_ip.split(".")
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
        first == 127
        or first == 10
        or (first == 192 and second == 168)
        or (first == 172 and 16 <= second <= 31)
    )


def _torch_load(path: str | Path) -> dict[str, Any]:
    import torch

    try:
        return torch.load(path, map_location="cpu", weights_only=False)
    except TypeError:
        return torch.load(path, map_location="cpu")


def load_model(model_path: str | Path) -> tuple[Any, dict[str, Any]]:
    from models.train_mlp import TrafficMLP

    checkpoint = _torch_load(model_path)
    model = TrafficMLP(
        input_dim=int(checkpoint["input_dim"]),
        hidden_units=int(checkpoint.get("hidden_units", 32)),
        dropout=float(checkpoint.get("dropout", 0.0)),
    )
    model.load_state_dict(checkpoint["model_state"])
    model.eval()
    return model, checkpoint


def _scale_features(features: np.ndarray, scaler_state: dict[str, list[float]]) -> np.ndarray:
    mean = np.asarray(scaler_state["mean"], dtype=np.float32)
    scale = np.asarray(scaler_state["scale"], dtype=np.float32)
    scale = np.where(scale == 0, 1.0, scale)
    return (features - mean) / scale


def _sigmoid(values: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(values, -60, 60)))


def _layer_prefix_sort_key(prefix: str) -> tuple[Any, ...]:
    parts: list[Any] = []
    for part in prefix.split("."):
        parts.append(int(part) if part.isdigit() else part)
    return tuple(parts)


def export_fast_model(model_path: str | Path, output_path: str | Path) -> dict[str, Any]:
    checkpoint = _torch_load(model_path)
    model_state = checkpoint["model_state"]
    prefixes = sorted(
        {key.rsplit(".", 1)[0] for key in model_state if key.endswith(".weight")},
        key=_layer_prefix_sort_key,
    )
    layers = []
    for prefix in prefixes:
        weight = model_state[f"{prefix}.weight"].detach().cpu().numpy().astype(float)
        bias = model_state[f"{prefix}.bias"].detach().cpu().numpy().astype(float)
        layers.append({"weight": weight.tolist(), "bias": bias.tolist()})

    payload = {
        "format": FAST_MODEL_FORMAT,
        "input_dim": int(checkpoint["input_dim"]),
        "hidden_units": int(checkpoint.get("hidden_units", 32)),
        "dropout": float(checkpoint.get("dropout", 0.0)),
        "feature_columns": list(checkpoint["feature_columns"]),
        "scaler": checkpoint["scaler"],
        "decision_threshold": float(checkpoint.get("decision_threshold", 0.80)),
        "layers": layers,
    }
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def load_fast_model(model_path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(model_path).read_text(encoding="utf-8"))
    if payload.get("format") != FAST_MODEL_FORMAT:
        raise ValueError(f"{model_path} is not a {FAST_MODEL_FORMAT} model")
    if not payload.get("layers"):
        raise ValueError(f"{model_path} does not contain MLP layers")
    return payload


def predict_probabilities_fast(input_path: str | Path, model_path: str | Path) -> tuple[np.ndarray, Any, dict[str, Any]]:
    frame = load_feature_csv(input_path)
    model = load_fast_model(model_path)
    feature_columns = list(model["feature_columns"])
    x = _scale_features(feature_matrix(frame, feature_columns), model["scaler"]).astype(np.float32)

    for layer in model["layers"][:-1]:
        weight = np.asarray(layer["weight"], dtype=np.float32)
        bias = np.asarray(layer["bias"], dtype=np.float32)
        x = np.maximum(x @ weight.T + bias, 0.0)

    output_layer = model["layers"][-1]
    output_weight = np.asarray(output_layer["weight"], dtype=np.float32)
    output_bias = np.asarray(output_layer["bias"], dtype=np.float32)
    logits = (x @ output_weight.T + output_bias).reshape(-1)
    return _sigmoid(logits), frame, model


def predict_probabilities_torch(input_path: str | Path, model_path: str | Path) -> tuple[np.ndarray, Any, dict[str, Any]]:
    import torch

    frame = load_feature_csv(input_path)
    model, checkpoint = load_model(model_path)
    feature_columns = list(checkpoint["feature_columns"])
    x = _scale_features(feature_matrix(frame, feature_columns), checkpoint["scaler"]).astype(np.float32)
    with torch.no_grad():
        probabilities = torch.sigmoid(model(torch.tensor(x, dtype=torch.float32))).cpu().numpy()
    return probabilities, frame, checkpoint


def predict_probabilities(input_path: str | Path, model_path: str | Path) -> tuple[np.ndarray, Any, dict[str, Any]]:
    if Path(model_path).suffix.lower() == ".json":
        return predict_probabilities_fast(input_path, model_path)
    return predict_probabilities_torch(input_path, model_path)


def run_inference(
    input_path: str | Path,
    model_path: str | Path,
    output_path: str | Path,
    threshold: float | None = 0.80,
) -> dict[str, Any]:
    probabilities, frame, checkpoint = predict_probabilities(input_path, model_path)
    decision_threshold = float(checkpoint.get("decision_threshold", 0.80) if threshold is None else threshold)
    working = frame.copy()
    working["_attack_probability"] = probabilities

    decisions = []
    for src_ip, group in working.groupby("src_ip", sort=True):
        if not _is_defense_actionable_source(str(src_ip)):
            continue
        confidence = float(group["_attack_probability"].max())
        if confidence < decision_threshold:
            continue
        attack_type = source_attack_type(group)
        decisions.append(
            {
                "src_ip": str(src_ip),
                "label": "attack",
                "attack_type": attack_type,
                "confidence": round(confidence, 6),
                "action": "block",
                "reason": f"model_detected_{attack_type}",
            }
        )

    result = {
        "generated_at": datetime.now(PROJECT_TIMEZONE).isoformat(),
        "threshold": decision_threshold,
        "decisions": decisions,
    }
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    persist_decision_report(
        result,
        output_path=output,
        input_path=input_path,
        model_path=model_path,
    )
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Infer attack sources with a trained Project 9 MLP.")
    parser.add_argument("--input", required=True, help="Input feature CSV.")
    parser.add_argument("--model", required=True, help="Trained model .pth path.")
    parser.add_argument("--output", required=True, help="Output decision JSON.")
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Attack probability threshold. Defaults to the model checkpoint threshold, then 0.80.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run_inference(
            input_path=args.input,
            model_path=args.model,
            output_path=args.output,
            threshold=args.threshold,
        )
    except StorageError as exc:
        print(f"[storage][error] {exc}", flush=True)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
