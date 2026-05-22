"""Run MLP inference and emit defense decisions."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import torch

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from models.feature_utils import feature_matrix, load_feature_csv, scaler_from_state, source_attack_type
from models.train_mlp import TrafficMLP


def _torch_load(path: str | Path) -> dict[str, Any]:
    try:
        return torch.load(path, map_location="cpu", weights_only=False)
    except TypeError:
        return torch.load(path, map_location="cpu")


def load_model(model_path: str | Path) -> tuple[TrafficMLP, dict[str, Any]]:
    checkpoint = _torch_load(model_path)
    model = TrafficMLP(
        input_dim=int(checkpoint["input_dim"]),
        hidden_units=int(checkpoint.get("hidden_units", 32)),
        dropout=float(checkpoint.get("dropout", 0.0)),
    )
    model.load_state_dict(checkpoint["model_state"])
    model.eval()
    return model, checkpoint


def predict_probabilities(input_path: str | Path, model_path: str | Path) -> tuple[np.ndarray, Any, dict[str, Any]]:
    frame = load_feature_csv(input_path)
    model, checkpoint = load_model(model_path)
    feature_columns = list(checkpoint["feature_columns"])
    scaler = scaler_from_state(checkpoint["scaler"])
    x = scaler.transform(feature_matrix(frame, feature_columns)).astype(np.float32)
    with torch.no_grad():
        probabilities = torch.sigmoid(model(torch.tensor(x, dtype=torch.float32))).cpu().numpy()
    return probabilities, frame, checkpoint


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
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "threshold": decision_threshold,
        "decisions": decisions,
    }
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
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
    result = run_inference(
        input_path=args.input,
        model_path=args.model,
        output_path=args.output,
        threshold=args.threshold,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
