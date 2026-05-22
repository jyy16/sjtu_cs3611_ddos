# SOTA-Inspired Project 9 Model Upgrade

## Goal

Implement a stronger, course-runnable "SOTA-inspired" model stack for Project 9:
supervised MLP, unsupervised AutoEncoder, KMeans, and a fused evaluation report.

## Phases

1. Status: complete - Review current model and SOTA direction.
2. Status: complete - Add failing tests for AutoEncoder and fusion outputs.
3. Status: complete - Implement AutoEncoder anomaly detector with checkpoints.
4. Status: complete - Implement fusion pipeline and report generation.
5. Status: complete - Refresh demo artifacts and verify all commands/tests.

## Decisions

- Keep the existing MLP and KMeans APIs stable.
- Add AutoEncoder rather than replacing KMeans because Project 9 explicitly accepts KMeans or AutoEncoder, and having both is stronger for demonstration.
- Use only existing dependencies: numpy, pandas, scikit-learn, PyTorch.
- Avoid claiming real academic SOTA without real PCAP datasets and external validation.

## Errors Encountered

| Error | Attempt | Resolution |
| --- | --- | --- |
| Missing `models.anomaly_autoencoder` | RED test | Added AutoEncoder module. |
| Missing `models.sota_fusion` | RED test | Added fusion module. |
