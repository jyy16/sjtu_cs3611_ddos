# Project 9 Model Quality Report

## Conclusion

The model module satisfies the Project 9 model-development rubric for the
updated attack/defense integration: it extracts statistical features from the
new PCAP captures, trains a checkpointed MLP classifier for `normal` vs
`attack`, emits defense-actionable `decision.json`, and refreshes the
unsupervised anomaly-detection reports with KMeans and AutoEncoder.

This is a strong course-demo pipeline rather than a claim of academic
state-of-the-art on public DDoS benchmarks. The current PCAP normal set is small,
so report the metrics as Project 9 demo validation results.

## Implemented Capabilities

- PCAP/PCAPNG feature extraction through `features/extract_features.py`.
- Required feature schema in `features/feature_schema.md`.
- PyTorch MLP classifier through `models/train_mlp.py`.
- Defense-ready inference through `models/infer.py`.
- Inference filters decisions to sources the defense module can act on:
  `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`.
- KMeans anomaly detection for high-rate traffic separation.
- AutoEncoder anomaly detection trained on normal traffic reconstruction error.
- SOTA-inspired fusion report combining MLP, AutoEncoder, and KMeans signals.
- Checkpointing for neural models: latest, best, and periodic epoch checkpoints.

## Updated PCAP Training Data

Generated from the updated attack module captures:

- Normal PCAP: `attacks/PCAP/normal_traffic.pcap`
- Attack PCAP: `attacks/PCAP/attack_traffic.pcap`
- Normal features: `data/features/demo/normal_traffic.csv` with 21 rows
- Attack features: `data/features/demo/attack_before_defense.csv` with 1680 rows
- Training CSV: `data/features/train.csv` with 1701 rows
- Target IP filter: `127.0.0.1`

## MLP Classifier Results

Command used:

```bash
python models/train_mlp.py \
  --input data/features/train.csv \
  --output models/saved/model.pth \
  --metrics-out data/logs/demo/train_metrics.json \
  --checkpoint-dir models/saved/checkpoints \
  --checkpoint-every 10 \
  --epochs 160 \
  --patience 40 \
  --seed 42 \
  --hidden-units 64 \
  --dropout 0.1 \
  --weight-decay 0.0001 \
  --lr 0.005
```

Current validation metrics from `data/logs/demo/train_metrics.json`:

- Accuracy: 1.0
- Precision: 1.0
- Recall: 1.0
- F1: 1.0
- ROC-AUC: 1.0
- Confusion matrix: TN=5, FP=0, FN=0, TP=421
- Best epoch: 35
- Epochs run: 75
- Best threshold: 0.5

Checkpoint outputs:

- `models/saved/model.pth`
- `models/saved/checkpoints/best_model.pth`
- `models/saved/checkpoints/latest.pth`
- `models/saved/checkpoints/epoch_010.pth` and later periodic checkpoints

## Defense Decision Output

Command used:

```bash
python models/infer.py \
  --input data/features/demo/attack_before_defense.csv \
  --model models/saved/model.pth \
  --output data/logs/demo/decision.json \
  --threshold 0.80
```

Current `decision.json` contains 10 attack decisions after filtering to
sources accepted by `defense/block_ip.sh`. This avoids sending public spoofed IPs
to the defense module, which intentionally refuses to block public addresses.

## Unsupervised And Fusion Results

Command used:

```bash
python models/sota_fusion.py \
  --input data/features/train.csv \
  --output data/logs/demo/sota_report.json \
  --model-dir models/saved/sota \
  --epochs 100 \
  --contamination 0.05 \
  --seed 42
```

Current fusion metrics from `data/logs/demo/sota_report.json`:

- Fusion accuracy: 0.9994
- Fusion precision: 0.9994
- Fusion recall: 1.0
- Fusion F1: 0.9997
- Fusion ROC-AUC: 1.0
- Fusion threshold: 0.17

Component metrics:

- MLP: accuracy 1.0, precision 1.0, recall 1.0, F1 1.0, ROC-AUC 1.0
- AutoEncoder: precision 0.9994, recall 1.0, F1 0.9997, ROC-AUC 1.0
- KMeans: precision 1.0, recall 0.0119, cluster purity 0.9877,
  silhouette 0.8883

## Remaining Caveat

The updated attack capture is much larger than the normal capture. For a more
credible external SOTA claim, collect more normal PCAP sessions and evaluate on a
session-level holdout set. For Project 9, the current artifacts are reproducible,
checkpointed, and integrated with the required demo commands.
