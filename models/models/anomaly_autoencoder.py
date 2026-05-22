"""AutoEncoder anomaly detection for Project 9 traffic features."""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from torch import nn

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from models.feature_utils import NUMERIC_FEATURES, feature_matrix, load_feature_csv, scaler_to_state


class TrafficAutoEncoder(nn.Module):
    def __init__(self, input_dim: int, latent_dim: int = 3, hidden_units: int = 16) -> None:
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_units),
            nn.ReLU(),
            nn.Linear(hidden_units, latent_dim),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_units),
            nn.ReLU(),
            nn.Linear(hidden_units, input_dim),
        )

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(features))


def _set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def _clone_state_dict(model: nn.Module) -> dict[str, torch.Tensor]:
    return {name: value.detach().cpu().clone() for name, value in model.state_dict().items()}


def _reconstruction_errors(model: TrafficAutoEncoder, x: np.ndarray) -> np.ndarray:
    model.eval()
    with torch.no_grad():
        tensor = torch.tensor(x, dtype=torch.float32)
        reconstructed = model(tensor)
        errors = torch.mean((reconstructed - tensor) ** 2, dim=1)
    return errors.cpu().numpy()


def _labels_if_available(frame: pd.DataFrame) -> np.ndarray | None:
    if "label" not in frame.columns:
        return None
    labels = frame["label"].astype(str).str.lower().map({"normal": 0, "attack": 1})
    if labels.isna().any():
        return None
    return labels.to_numpy(dtype=int)


def _threshold_from_normal_errors(errors: np.ndarray, contamination: float) -> float:
    if len(errors) == 0:
        return 0.0
    quantile = max(0.50, min(0.999, 1.0 - contamination))
    return float(np.quantile(errors, quantile))


def _metrics(errors: np.ndarray, threshold: float, labels: np.ndarray | None) -> dict[str, float | None]:
    if labels is None:
        return {
            "anomaly_precision": None,
            "anomaly_recall": None,
            "anomaly_f1": None,
            "roc_auc": None,
        }
    predicted = errors > threshold
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels,
        predicted.astype(int),
        average="binary",
        zero_division=0,
    )
    try:
        roc_auc = float(roc_auc_score(labels, errors))
    except ValueError:
        roc_auc = 0.0
    return {
        "anomaly_precision": float(precision),
        "anomaly_recall": float(recall),
        "anomaly_f1": float(f1),
        "roc_auc": roc_auc,
    }


def _checkpoint_payload(
    model_state: dict[str, torch.Tensor],
    input_dim: int,
    latent_dim: int,
    hidden_units: int,
    scaler_state: dict[str, list[float]],
    threshold: float,
    best_epoch: int,
    history: list[dict[str, float | int]],
) -> dict[str, Any]:
    return {
        "model_state": model_state,
        "input_dim": input_dim,
        "latent_dim": latent_dim,
        "hidden_units": hidden_units,
        "feature_columns": NUMERIC_FEATURES,
        "scaler": scaler_state,
        "threshold": float(threshold),
        "best_epoch": int(best_epoch),
        "history": history,
    }


def train_autoencoder_anomaly(
    input_path: str | Path,
    output_path: str | Path,
    model_out: str | Path,
    checkpoint_dir: str | Path | None = None,
    epochs: int = 100,
    lr: float = 0.01,
    latent_dim: int = 3,
    hidden_units: int = 16,
    contamination: float = 0.05,
    seed: int = 42,
    checkpoint_every: int = 10,
    patience: int = 20,
) -> dict[str, Any]:
    _set_seed(seed)
    frame = load_feature_csv(input_path)
    labels = _labels_if_available(frame)
    x_raw = feature_matrix(frame, NUMERIC_FEATURES)
    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(x_raw).astype(np.float32)
    scaler_state = scaler_to_state(scaler)

    normal_mask = frame["label"].astype(str).str.lower().eq("normal").to_numpy() if "label" in frame.columns else None
    train_pool = x_scaled[normal_mask] if normal_mask is not None and normal_mask.any() else x_scaled
    if len(train_pool) < 4:
        train_x = valid_x = train_pool
    else:
        train_x, valid_x = train_test_split(train_pool, test_size=0.25, random_state=seed)

    model = TrafficAutoEncoder(input_dim=x_scaled.shape[1], latent_dim=latent_dim, hidden_units=hidden_units)
    criterion = nn.MSELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    train_tensor = torch.tensor(train_x, dtype=torch.float32)
    valid_tensor = torch.tensor(valid_x, dtype=torch.float32)

    checkpoints = Path(checkpoint_dir) if checkpoint_dir else None
    if checkpoints is not None:
        checkpoints.mkdir(parents=True, exist_ok=True)

    history: list[dict[str, float | int]] = []
    best_loss = float("inf")
    best_epoch = 0
    best_state = _clone_state_dict(model)
    stagnant_epochs = 0

    for epoch in range(1, epochs + 1):
        model.train()
        optimizer.zero_grad()
        reconstructed = model(train_tensor)
        loss = criterion(reconstructed, train_tensor)
        loss.backward()
        optimizer.step()

        model.eval()
        with torch.no_grad():
            valid_loss = float(criterion(model(valid_tensor), valid_tensor).item())
        history.append({"epoch": int(epoch), "train_loss": float(loss.item()), "valid_loss": valid_loss})

        if valid_loss < best_loss:
            best_loss = valid_loss
            best_epoch = epoch
            best_state = _clone_state_dict(model)
            stagnant_epochs = 0
        else:
            stagnant_epochs += 1

        if checkpoints is not None:
            latest_errors = _reconstruction_errors(model, train_pool)
            latest_threshold = _threshold_from_normal_errors(latest_errors, contamination)
            latest_payload = _checkpoint_payload(
                _clone_state_dict(model),
                x_scaled.shape[1],
                latent_dim,
                hidden_units,
                scaler_state,
                latest_threshold,
                epoch,
                history,
            )
            torch.save(latest_payload, checkpoints / "latest.pth")
            if checkpoint_every > 0 and epoch % checkpoint_every == 0:
                torch.save(latest_payload, checkpoints / f"epoch_{epoch:03d}.pth")

        if stagnant_epochs >= patience:
            break

    model.load_state_dict(best_state)
    normal_errors = _reconstruction_errors(model, train_pool)
    threshold = _threshold_from_normal_errors(normal_errors, contamination)
    errors = _reconstruction_errors(model, x_scaled)
    predicted = errors > threshold
    metric_values = _metrics(errors, threshold, labels)

    assignments = []
    for idx, row in frame.iterrows():
        assignments.append(
            {
                "row": int(idx),
                "src_ip": str(row.get("src_ip", "")),
                "reconstruction_error": float(errors[idx]),
                "is_anomaly": bool(predicted[idx]),
                "label": str(row.get("label", "")),
            }
        )

    report = {
        "threshold": float(threshold),
        "best_epoch": int(best_epoch),
        "epochs_ran": int(len(history)),
        "history": history,
        **metric_values,
        "assignments": assignments,
    }

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")

    payload = _checkpoint_payload(
        best_state,
        x_scaled.shape[1],
        latent_dim,
        hidden_units,
        scaler_state,
        threshold,
        best_epoch,
        history,
    )
    model_path = Path(model_out)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(payload, model_path)
    if checkpoints is not None:
        torch.save(payload, checkpoints / "best_model.pth")

    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train an AutoEncoder anomaly detector on traffic features.")
    parser.add_argument("--input", required=True, help="Input feature CSV.")
    parser.add_argument("--output", required=True, help="Output anomaly report JSON.")
    parser.add_argument("--model-out", required=True, help="Output AutoEncoder .pth path.")
    parser.add_argument("--checkpoint-dir", default=None, help="Directory for AutoEncoder checkpoints.")
    parser.add_argument("--epochs", type=int, default=100, help="Training epochs.")
    parser.add_argument("--lr", type=float, default=0.01, help="Adam learning rate.")
    parser.add_argument("--latent-dim", type=int, default=3, help="AutoEncoder latent dimension.")
    parser.add_argument("--hidden-units", type=int, default=16, help="AutoEncoder hidden width.")
    parser.add_argument("--contamination", type=float, default=0.05, help="Expected anomaly fraction.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed.")
    parser.add_argument("--checkpoint-every", type=int, default=10, help="Save epoch_NNN.pth every N epochs.")
    parser.add_argument("--patience", type=int, default=20, help="Early stopping patience.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = train_autoencoder_anomaly(
        input_path=args.input,
        output_path=args.output,
        model_out=args.model_out,
        checkpoint_dir=args.checkpoint_dir,
        epochs=args.epochs,
        lr=args.lr,
        latent_dim=args.latent_dim,
        hidden_units=args.hidden_units,
        contamination=args.contamination,
        seed=args.seed,
        checkpoint_every=args.checkpoint_every,
        patience=args.patience,
    )
    compact = {key: value for key, value in report.items() if key not in {"assignments", "history"}}
    print(json.dumps(compact, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
