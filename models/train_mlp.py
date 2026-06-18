"""Train a compact PyTorch MLP to classify normal vs attack traffic."""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from torch import nn

if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from models.feature_utils import LABEL_TO_ID, NUMERIC_FEATURES, feature_matrix, labels_from_frame, load_feature_csv, scaler_to_state


class TrafficMLP(nn.Module):
    def __init__(self, input_dim: int, hidden_units: int = 32, dropout: float = 0.0) -> None:
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_dim, hidden_units),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_units, max(8, hidden_units // 2)),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(max(8, hidden_units // 2), 1),
        )

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        return self.network(features).squeeze(-1)


def _set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def _split_data(
    x: np.ndarray,
    y: np.ndarray,
    test_size: float,
    seed: int,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    class_counts = np.bincount(y.astype(int), minlength=2)
    can_stratify = len(y) >= 8 and np.all(class_counts >= 2)
    if not can_stratify:
        return x, x, y, y
    return train_test_split(
        x,
        y,
        test_size=test_size,
        random_state=seed,
        stratify=y,
    )


def _metrics(y_true: np.ndarray, probabilities: np.ndarray, threshold: float = 0.5) -> dict[str, float | dict[str, int]]:
    predicted = (probabilities >= threshold).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true.astype(int),
        predicted,
        average="binary",
        zero_division=0,
    )
    tn, fp, fn, tp = confusion_matrix(y_true.astype(int), predicted, labels=[0, 1]).ravel()
    try:
        roc_auc = float(roc_auc_score(y_true.astype(int), probabilities))
    except ValueError:
        roc_auc = 0.0
    return {
        "accuracy": float(accuracy_score(y_true.astype(int), predicted)),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "roc_auc": roc_auc,
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
    }


def _best_threshold(y_true: np.ndarray, probabilities: np.ndarray) -> tuple[float, dict[str, float | dict[str, int]]]:
    best_threshold = 0.5
    best_metrics = _metrics(y_true, probabilities, threshold=best_threshold)
    best_key = (float(best_metrics["f1"]), float(best_metrics["recall"]), float(best_metrics["accuracy"]))
    for threshold in np.linspace(0.05, 0.95, 91):
        candidate = _metrics(y_true, probabilities, threshold=float(threshold))
        candidate_key = (float(candidate["f1"]), float(candidate["recall"]), float(candidate["accuracy"]))
        if candidate_key > best_key:
            best_threshold = float(round(float(threshold), 2))
            best_metrics = candidate
            best_key = candidate_key
    return best_threshold, best_metrics


def _clone_state_dict(model: nn.Module) -> dict[str, torch.Tensor]:
    return {name: value.detach().cpu().clone() for name, value in model.state_dict().items()}


def _checkpoint_payload(
    model_state: dict[str, torch.Tensor],
    input_dim: int,
    hidden_units: int,
    dropout: float,
    scaler_state: dict[str, list[float]],
    epoch: int,
    metrics: dict[str, float | dict[str, int]],
    decision_threshold: float,
    history: list[dict[str, float | int]],
) -> dict[str, object]:
    return {
        "model_state": model_state,
        "input_dim": input_dim,
        "hidden_units": hidden_units,
        "dropout": dropout,
        "feature_columns": NUMERIC_FEATURES,
        "scaler": scaler_state,
        "label_to_id": LABEL_TO_ID,
        "decision_threshold": decision_threshold,
        "best_epoch": int(epoch),
        "metrics": metrics,
        "history": history,
    }


def train_from_csv(
    input_path: str | Path,
    output_path: str | Path,
    metrics_out: str | Path,
    epochs: int = 120,
    lr: float = 0.01,
    hidden_units: int = 32,
    dropout: float = 0.0,
    weight_decay: float = 0.0,
    test_size: float = 0.25,
    seed: int = 42,
    checkpoint_dir: str | Path | None = None,
    checkpoint_every: int = 10,
    patience: int | None = 25,
    min_delta: float = 0.0001,
) -> dict[str, object]:
    _set_seed(seed)
    frame = load_feature_csv(input_path)
    x_raw = feature_matrix(frame, NUMERIC_FEATURES)
    y = labels_from_frame(frame)
    if len(np.unique(y)) != 2:
        raise ValueError("training data must contain both normal and attack labels")

    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(x_raw).astype(np.float32)
    scaler_state = scaler_to_state(scaler)
    x_train, x_valid, y_train, y_valid = _split_data(x_scaled, y, test_size=test_size, seed=seed)

    model = TrafficMLP(input_dim=x_train.shape[1], hidden_units=hidden_units, dropout=dropout)
    positives = max(float(y_train.sum()), 1.0)
    negatives = max(float(len(y_train) - y_train.sum()), 1.0)
    criterion = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([negatives / positives], dtype=torch.float32))
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=weight_decay)

    train_x = torch.tensor(x_train, dtype=torch.float32)
    train_y = torch.tensor(y_train, dtype=torch.float32)
    valid_x = torch.tensor(x_valid, dtype=torch.float32)
    valid_y = torch.tensor(y_valid, dtype=torch.float32)

    checkpoints = Path(checkpoint_dir) if checkpoint_dir else None
    if checkpoints is not None:
        checkpoints.mkdir(parents=True, exist_ok=True)

    history: list[dict[str, float | int]] = []
    best_state = _clone_state_dict(model)
    best_metrics: dict[str, float | dict[str, int]] = _metrics(y_valid, np.zeros_like(y_valid), threshold=0.5)
    best_threshold = 0.5
    best_epoch = 0
    best_valid_loss = float("inf")
    best_score = -1.0
    epochs_without_improvement = 0

    for epoch in range(1, epochs + 1):
        model.train()
        optimizer.zero_grad()
        logits = model(train_x)
        loss = criterion(logits, train_y)
        loss.backward()
        optimizer.step()

        model.eval()
        with torch.no_grad():
            valid_logits = model(valid_x)
            valid_loss = float(criterion(valid_logits, valid_y).item())
            probabilities = torch.sigmoid(valid_logits).cpu().numpy()
        threshold, metrics = _best_threshold(y_valid, probabilities)
        history_row = {
            "epoch": int(epoch),
            "train_loss": float(loss.item()),
            "valid_loss": valid_loss,
            "threshold": float(threshold),
            "accuracy": float(metrics["accuracy"]),
            "precision": float(metrics["precision"]),
            "recall": float(metrics["recall"]),
            "f1": float(metrics["f1"]),
            "roc_auc": float(metrics["roc_auc"]),
        }
        history.append(history_row)

        score = float(metrics["f1"])
        improved = score > best_score or (abs(score - best_score) <= min_delta and valid_loss < best_valid_loss - min_delta)
        if improved:
            best_score = score
            best_valid_loss = valid_loss
            best_state = _clone_state_dict(model)
            best_metrics = metrics
            best_threshold = threshold
            best_epoch = epoch
            epochs_without_improvement = 0
            if checkpoints is not None:
                torch.save(
                    _checkpoint_payload(
                        best_state,
                        x_train.shape[1],
                        hidden_units,
                        dropout,
                        scaler_state,
                        best_epoch,
                        best_metrics,
                        best_threshold,
                        history,
                    ),
                    checkpoints / "best_model.pth",
                )
        else:
            epochs_without_improvement += 1

        if checkpoints is not None:
            latest_payload = _checkpoint_payload(
                _clone_state_dict(model),
                x_train.shape[1],
                hidden_units,
                dropout,
                scaler_state,
                epoch,
                metrics,
                threshold,
                history,
            )
            torch.save(latest_payload, checkpoints / "latest.pth")
            if checkpoint_every > 0 and epoch % checkpoint_every == 0:
                torch.save(latest_payload, checkpoints / f"epoch_{epoch:03d}.pth")

        if patience is not None and epochs_without_improvement >= patience:
            break

    metrics = {
        "accuracy": float(best_metrics["accuracy"]),
        "precision": float(best_metrics["precision"]),
        "recall": float(best_metrics["recall"]),
        "f1": float(best_metrics["f1"]),
        "roc_auc": float(best_metrics["roc_auc"]),
        "confusion_matrix": best_metrics["confusion_matrix"],
        "best_threshold": float(best_threshold),
        "best_epoch": int(best_epoch),
        "epochs_ran": int(len(history)),
        "history": history,
    }

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    torch.save(
        _checkpoint_payload(
            best_state,
            x_train.shape[1],
            hidden_units,
            dropout,
            scaler_state,
            best_epoch,
            best_metrics,
            best_threshold,
            history,
        ),
        output,
    )

    metrics_path = Path(metrics_out)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train a Project 9 MLP attack classifier.")
    parser.add_argument("--input", required=True, help="Training feature CSV.")
    parser.add_argument("--output", required=True, help="Output model .pth path.")
    parser.add_argument("--metrics-out", required=True, help="Output training metrics JSON.")
    parser.add_argument("--epochs", type=int, default=120, help="Training epochs.")
    parser.add_argument("--lr", type=float, default=0.01, help="Adam learning rate.")
    parser.add_argument("--hidden-units", type=int, default=32, help="Hidden units in the first layer.")
    parser.add_argument("--dropout", type=float, default=0.0, help="Dropout probability between MLP layers.")
    parser.add_argument("--weight-decay", type=float, default=0.0, help="Adam weight decay.")
    parser.add_argument("--test-size", type=float, default=0.25, help="Validation split fraction.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed.")
    parser.add_argument("--checkpoint-dir", default=None, help="Directory for latest/best/periodic checkpoints.")
    parser.add_argument("--checkpoint-every", type=int, default=10, help="Save epoch_NNN.pth every N epochs.")
    parser.add_argument("--patience", type=int, default=25, help="Early-stopping patience in epochs.")
    parser.add_argument("--min-delta", type=float, default=0.0001, help="Minimum validation-loss improvement.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    metrics = train_from_csv(
        input_path=args.input,
        output_path=args.output,
        metrics_out=args.metrics_out,
        epochs=args.epochs,
        lr=args.lr,
        hidden_units=args.hidden_units,
        dropout=args.dropout,
        weight_decay=args.weight_decay,
        test_size=args.test_size,
        seed=args.seed,
        checkpoint_dir=args.checkpoint_dir,
        checkpoint_every=args.checkpoint_every,
        patience=args.patience,
        min_delta=args.min_delta,
    )
    print(json.dumps(metrics, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
