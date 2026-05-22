#!/bin/sh
set -eu

part="${1:-model}"

if [ "$part" != "model" ]; then
  echo "This checkout contains the Project 9 model-development module. Use: $0 model" >&2
  exit 2
fi

for file in \
  features/extract_features.py \
  features/feature_schema.md \
  models/train_mlp.py \
  models/infer.py \
  models/anomaly_kmeans.py \
  models/anomaly_autoencoder.py \
  models/sota_fusion.py \
  requirements.txt
do
  if [ ! -f "$file" ]; then
    echo "missing required file: $file" >&2
    exit 1
  fi
done

python features/extract_features.py --help >/dev/null
python models/train_mlp.py --help >/dev/null
python models/infer.py --help >/dev/null
python models/anomaly_kmeans.py --help >/dev/null
python models/anomaly_autoencoder.py --help >/dev/null
python models/sota_fusion.py --help >/dev/null

echo "model contract OK"
