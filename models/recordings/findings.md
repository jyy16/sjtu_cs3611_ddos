# Findings

## Project Context

- Existing Project 9 model module already has PCAP feature extraction, MLP training,
  MLP inference, KMeans anomaly detection, checkpointed MLP training, and tests.
- Gap for a stronger SOTA-like course implementation: no deep AutoEncoder anomaly
  detector and no single fused report comparing MLP, KMeans, and AutoEncoder.

## Research Notes

- Deep AutoEncoder-style reconstruction error is commonly used for network
  anomaly detection because it can learn a normal-traffic manifold and flag
  high-error unknown traffic without requiring attack labels.
- Literature support checked during implementation:
  - Scientific Reports 2024 describes a traffic anomaly model that fuses CNN
    and AutoEncoder signals.
  - SpringerOpen Cybersecurity 2022 discusses AutoEncoder anomaly detection
    through vector reconstruction error.
  - Springer Wireless Networks work on DDoS detection describes raising alarms
    when flow reconstruction error exceeds a decision threshold.
- For a course project with tabular statistical traffic features, a compact
  fully connected AutoEncoder is the best cost/benefit choice: easy to run,
  easy to checkpoint, and directly aligned with the Project 9 optional
  "K-Means or AutoEncoder" requirement.

## Implementation Direction

- Add `models/anomaly_autoencoder.py`.
- Add `models/sota_fusion.py`.
- Add tests for checkpointed AE training and fused model report.

## Demo Evidence

- `models/sota_fusion.py` on `data/features/demo/synthetic_train.csv` produced
  fusion F1 1.0, precision 1.0, recall 1.0, ROC-AUC 1.0.
- AutoEncoder component with contamination 0.01 produced precision 0.9804,
  recall 1.0, F1 0.9901, ROC-AUC 1.0 on the synthetic demo data.
