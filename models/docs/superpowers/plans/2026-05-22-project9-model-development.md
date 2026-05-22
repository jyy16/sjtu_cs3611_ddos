# Project 9 Model Development Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Project 9 model-development module: PCAP feature extraction, supervised MLP attack classification, and unsupervised anomaly separation.

**Architecture:** `features/` owns packet parsing and windowed statistical feature generation. `models/` owns reusable feature preprocessing, MLP training/inference, and KMeans anomaly detection. `tests/` uses synthetic PCAP and feature CSV fixtures to validate the command contracts without needing live attack traffic.

**Tech Stack:** Python 3.13, pandas, numpy, scikit-learn, PyTorch, pytest, standard-library PCAP/PCAPNG parser.

---

### Task 1: Feature Extraction Contract

**Files:**
- Create: `features/__init__.py`
- Create: `features/extract_features.py`
- Create: `features/feature_schema.md`
- Test: `tests/test_feature_extraction.py`

- [ ] Write a failing pytest that builds a tiny Ethernet/IPv4/TCP PCAP with normal ACK packets and SYN flood packets, then asserts the CSV columns match the group contract and that attack windows have higher `pps` and `syn_ack_ratio`.
- [ ] Run `python -m pytest tests/test_feature_extraction.py -v` and confirm the import/behavior fails before implementation.
- [ ] Implement a lightweight PCAP/PCAPNG reader, IPv4/TCP/UDP decoding, entropy calculation, 1-second window aggregation, and CLI arguments `--input --output --label --attack-type --target-ip --window-size`.
- [ ] Run the feature extraction test until it passes.

### Task 2: Supervised MLP Classifier

**Files:**
- Create: `models/__init__.py`
- Create: `models/feature_utils.py`
- Create: `models/train_mlp.py`
- Create: `models/infer.py`
- Test: `tests/test_model_pipeline.py`

- [ ] Write failing tests with separable synthetic normal/attack feature rows, asserting `train_mlp.py` writes `model.pth` and metrics JSON with accuracy/F1 above 0.90.
- [ ] Add a failing inference test asserting `infer.py` produces `decision.json` with `label`, `confidence`, `action`, and `reason` for attack sources above threshold.
- [ ] Implement preprocessing, train/test split, `StandardScaler`, label encoding, a compact fully connected PyTorch model, saved checkpoint metadata, and inference aggregation by `src_ip`.
- [ ] Run `python -m pytest tests/test_model_pipeline.py -v` until it passes.

### Task 3: Unsupervised Anomaly Detection

**Files:**
- Create: `models/anomaly_kmeans.py`
- Test: `tests/test_anomaly_detection.py`

- [ ] Write a failing test with unlabeled mixed traffic features, asserting the KMeans report separates high-rate attack-like rows from normal rows with strong cluster purity.
- [ ] Implement `anomaly_kmeans.py` with CLI `--input --output --model-out --clusters`, scaler persistence, cluster-to-anomaly mapping by high PPS/SYN ratio score, and JSON metrics.
- [ ] Run `python -m pytest tests/test_anomaly_detection.py -v` until it passes.

### Task 4: Command-Level Verification

**Files:**
- Create: `requirements.txt`

- [ ] Run `python -m pytest -v`.
- [ ] Run `python features/extract_features.py --help`.
- [ ] Run `python models/train_mlp.py --help`.
- [ ] Run `python models/infer.py --help`.
- [ ] Run `python models/anomaly_kmeans.py --help`.
- [ ] Run an end-to-end demo on synthetic CSV fixtures and inspect metrics/decision JSON.
