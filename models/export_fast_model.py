#!/usr/bin/env python3
"""Export a trained PyTorch MLP checkpoint to a lightweight JSON inference model."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from models.infer import export_fast_model


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export a Project 9 MLP .pth checkpoint to fast JSON.")
    parser.add_argument("--model", required=True, help="Input trained model .pth path.")
    parser.add_argument("--output", required=True, help="Output fast JSON model path.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload = export_fast_model(args.model, args.output)
    print(
        json.dumps(
            {
                "output": args.output,
                "format": payload["format"],
                "layers": len(payload["layers"]),
                "features": payload["feature_columns"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
