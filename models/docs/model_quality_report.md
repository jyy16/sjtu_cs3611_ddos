# Project 9 Model Quality Report

## Conclusion

The model module is now strong for the Project 9 rubric, but it should not be
claimed as real academic state of the art unless it is trained and evaluated on
large, diverse, real captured PCAP datasets with an external holdout set.

For the course requirement, it goes beyond the stated baseline:

- Extracts statistical traffic features from PCAP/PCAPNG.
- Trains a PyTorch MLP classifier for `normal` vs `attack`.
- Produces defense-ready `decision.json` with source IP, confidence, action,
  attack type, and reason.
- Runs unsupervised KMeans anomaly separation for unknown high-rate traffic.
- Runs a checkpointed deep AutoEncoder anomaly detector using reconstruction
  error on traffic-feature vectors.
- Runs `models/sota_fusion.py`, a SOTA-inspired fusion pipeline combining MLP,
  AutoEncoder, and KMeans signals into one report and decision list.
- Records validation metrics, ROC-AUC, confusion matrix, training history,
  best validation threshold, early stopping, and checkpoints.

## Checkpoint Strategy

Training supports:

- `models/saved/checkpoints/latest.pth`: most recent epoch.
- `models/saved/checkpoints/best_model.pth`: best validation F1 checkpoint.
- `models/saved/checkpoints/epoch_NNN.pth`: periodic checkpoint every
  `--checkpoint-every` epochs.
- Final `models/saved/model.pth`: best validation checkpoint, not simply the
  last epoch.

Recommended command:

```bash
python models/train_mlp.py \
  --input data/features/train.csv \
  --output models/saved/model.pth \
  --metrics-out data/logs/demo/train_metrics.json \
  --checkpoint-dir models/saved/checkpoints \
  --checkpoint-every 10 \
  --epochs 120 \
  --seed 42
```

## Current Demo Evidence

The synthetic demo dataset is intentionally separable. It is useful for showing
the pipeline works, not for proving real-world generalization.

Current `data/features/demo/synthetic_train.csv` results:

- MLP: accuracy 1.0, F1 1.0, ROC-AUC 1.0.
- AutoEncoder: precision 0.9804, recall 1.0, F1 0.9901, ROC-AUC 1.0.
- KMeans: precision 1.0, recall 1.0, cluster purity 1.0, silhouette 0.9513.
- Fusion: accuracy 1.0, precision 1.0, recall 1.0, F1 1.0, ROC-AUC 1.0.

Current refreshed demo outputs:

- `data/logs/demo/train_metrics.json`
- `data/logs/demo/decision.json`
- `data/logs/demo/anomaly_report.json`
- `data/logs/demo/autoencoder_report.json`
- `data/logs/demo/sota_report.json`
- `models/saved/model.pth`
- `models/saved/autoencoder.pth`
- `models/saved/sota/`
- `models/saved/checkpoints/`

Recommended SOTA-inspired fusion command:

```bash
python models/sota_fusion.py \
  --input data/features/train.csv \
  --output data/logs/demo/sota_report.json \
  --model-dir models/saved/sota \
  --epochs 120 \
  --contamination 0.01 \
  --seed 42
```

## Remaining Work For True SOTA Claims

To make a credible state-of-the-art claim, add:

- Real PCAP captures from normal traffic, SYN flood, HTTP flood, UDP reflection,
  and mixed attacks.
- A strict train/validation/test split by capture session, not random rows only.
- Baselines such as Logistic Regression, Random Forest, KMeans, and MLP.
- Ablation study for feature groups such as PPS, byte rate, SYN/ACK ratio, and
  entropy.
- Robustness checks with unseen attack rates and unseen source IP ranges.

Until then, describe this as a reproducible Project 9 intelligent classifier
and anomaly detector with checkpointed training and validation reporting.
