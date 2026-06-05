#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate an offline classroom visualization for one DDoS demo run."""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from statistics import mean
from typing import Any


PHASES = {
    "normal": {
        "label": "正常流量",
        "tone": "ok",
        "csv_prefixes": ("normal_", "normal"),
        "pcap_prefixes": ("normal_", "normal"),
        "tcpdump_prefix": "tcpdump_normal",
    },
    "before": {
        "label": "攻击前",
        "tone": "danger",
        "csv_prefixes": ("attack_before_defense_", "attack_before_defense"),
        "pcap_prefixes": ("attack_before_defense_", "attack_before_defense"),
        "tcpdump_prefix": "tcpdump_attack_before_defense",
    },
    "after": {
        "label": "防御后",
        "tone": "shield",
        "csv_prefixes": ("attack_after_defense_", "attack_after_defense"),
        "pcap_prefixes": ("attack_after_defense_", "attack_after_defense"),
        "tcpdump_prefix": "tcpdump_attack_after_defense",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate an offline HTML dashboard for a Project 9 DDoS demo run."
    )
    parser.add_argument(
        "--run-id",
        help="Run id under data/features, data/logs, and data/pcap. Defaults to the latest complete run.",
    )
    parser.add_argument(
        "--output",
        help="Output HTML path. Defaults to data/logs/<run-id>/demo_visualization_<run-id>.html.",
    )
    parser.add_argument(
        "--title",
        default="DDoS 攻防课堂演示",
        help="Dashboard title.",
    )
    return parser.parse_args()


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value in (None, ""):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def parse_timestamp(value: str) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text[:19], fmt)
        except ValueError:
            continue
    return None


def latest_complete_run(root: Path) -> str:
    feature_root = root / "data" / "features"
    candidates: list[Path] = []
    if feature_root.exists():
        candidates = sorted(
            (p for p in feature_root.iterdir() if p.is_dir()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
    for candidate in candidates:
        names = [p.name for p in candidate.glob("*.csv")]
        has_normal = any(name.startswith("normal") for name in names)
        has_before = any(name.startswith("attack_before_defense") for name in names)
        has_after = any(name.startswith("attack_after_defense") for name in names)
        if has_normal and has_before and has_after:
            return candidate.name
    if candidates:
        return candidates[0].name
    raise SystemExit("No run directory found under data/features.")


def pick_file(directory: Path, prefixes: tuple[str, ...], suffix: str) -> Path | None:
    if not directory.exists():
        return None
    matches: list[Path] = []
    for prefix in prefixes:
        matches.extend(directory.glob(f"{prefix}*{suffix}"))
    if not matches:
        return None
    return sorted(set(matches), key=lambda p: (len(p.name), p.name))[0]


def read_csv_dicts(path: Path | None) -> list[dict[str, str]]:
    if not path or not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def summarize_features(path: Path | None, phase_label: str) -> dict[str, Any]:
    rows = read_csv_dicts(path)
    by_time: dict[str, dict[str, float]] = defaultdict(
        lambda: {"pps": 0.0, "bps": 0.0, "syn": 0.0, "ack": 0.0, "unique": 0.0}
    )
    protocols = Counter()
    labels = Counter()
    attack_types = Counter()
    top_sources: Counter[str] = Counter()
    source_pps: Counter[str] = Counter()

    for row in rows:
        timestamp = row.get("timestamp", "")
        protocols[row.get("protocol", "UNKNOWN") or "UNKNOWN"] += 1
        labels[row.get("label", "unknown") or "unknown"] += 1
        attack_types[row.get("attack_type", "unknown") or "unknown"] += 1
        src_ip = row.get("src_ip", "unknown") or "unknown"
        top_sources[src_ip] += 1
        source_pps[src_ip] += safe_float(row.get("pps"))

        bucket = by_time[timestamp]
        bucket["pps"] += safe_float(row.get("pps"))
        bucket["bps"] += safe_float(row.get("bps"))
        bucket["syn"] += safe_float(row.get("syn_count"))
        bucket["ack"] += safe_float(row.get("ack_count"))
        bucket["unique"] = max(bucket["unique"], safe_float(row.get("unique_src_ips")))

    ordered_times = sorted(by_time.keys(), key=lambda value: parse_timestamp(value) or datetime.min)
    timeline = [
        {
            "t": timestamp,
            "x": idx,
            "pps": round(by_time[timestamp]["pps"], 3),
            "bps": round(by_time[timestamp]["bps"], 3),
            "mbps": round(by_time[timestamp]["bps"] / 1_000_000, 6),
            "syn": round(by_time[timestamp]["syn"], 3),
            "ack": round(by_time[timestamp]["ack"], 3),
            "unique": round(by_time[timestamp]["unique"], 3),
        }
        for idx, timestamp in enumerate(ordered_times)
    ]

    def values(key: str) -> list[float]:
        return [safe_float(point.get(key)) for point in timeline]

    summary = {
        "phase": phase_label,
        "path": str(path) if path else "",
        "rows": len(rows),
        "windows": len(timeline),
        "labels": dict(labels),
        "attackTypes": dict(attack_types),
        "protocols": dict(protocols),
        "avgPps": round(mean(values("pps")), 3) if timeline else 0,
        "maxPps": round(max(values("pps")), 3) if timeline else 0,
        "avgMbps": round(mean(values("mbps")), 6) if timeline else 0,
        "maxMbps": round(max(values("mbps")), 6) if timeline else 0,
        "maxSyn": round(max(values("syn")), 3) if timeline else 0,
        "maxAck": round(max(values("ack")), 3) if timeline else 0,
        "maxUniqueSrc": round(max(values("unique")), 3) if timeline else 0,
        "topSources": [
            {"ip": ip, "rows": count, "pps": round(source_pps[ip], 3)}
            for ip, count in top_sources.most_common(8)
        ],
    }
    return {"summary": summary, "timeline": timeline}


def parse_tcpdump_log(path: Path | None) -> dict[str, Any]:
    result = {"path": str(path) if path else "", "captured": 0, "received": 0, "dropped": 0}
    if not path or not path.exists():
        return result
    text = path.read_text(encoding="utf-8", errors="replace")
    for key, pattern in {
        "captured": r"(\d+)\s+packets captured",
        "received": r"(\d+)\s+packets received by filter",
        "dropped": r"(\d+)\s+packets dropped by kernel",
    }.items():
        match = re.search(pattern, text)
        if match:
            result[key] = int(match.group(1))
    return result


def file_size_stats(path: Path | None) -> dict[str, Any]:
    if not path or not path.exists():
        return {"path": "", "bytes": 0, "mb": 0.0}
    size = path.stat().st_size
    return {"path": str(path), "bytes": size, "mb": round(size / 1_000_000, 3)}


def summarize_decisions(path: Path | None) -> dict[str, Any]:
    empty = {
        "path": str(path) if path else "",
        "generatedAt": "",
        "threshold": 0.8,
        "count": 0,
        "labels": {},
        "actions": {},
        "attackTypes": {},
        "confidence": {"min": 0, "max": 0, "avg": 0},
        "histogram": [],
        "topSources": [],
    }
    if not path or not path.exists():
        return empty
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    decisions = payload.get("decisions", [])
    confidences = [safe_float(item.get("confidence")) for item in decisions]
    labels = Counter(item.get("label", "unknown") for item in decisions)
    actions = Counter(item.get("action", "unknown") for item in decisions)
    attack_types = Counter(item.get("attack_type", "unknown") for item in decisions)
    sources = Counter(item.get("src_ip", "unknown") for item in decisions)
    bins = [0] * 10
    for confidence in confidences:
        idx = min(9, max(0, int(math.floor(confidence * 10))))
        bins[idx] += 1
    return {
        "path": str(path),
        "generatedAt": payload.get("generated_at", ""),
        "threshold": safe_float(payload.get("threshold"), 0.8),
        "count": len(decisions),
        "labels": dict(labels),
        "actions": dict(actions),
        "attackTypes": dict(attack_types),
        "confidence": {
            "min": round(min(confidences), 6) if confidences else 0,
            "max": round(max(confidences), 6) if confidences else 0,
            "avg": round(mean(confidences), 6) if confidences else 0,
        },
        "histogram": [
            {"label": f"{i / 10:.1f}-{(i + 1) / 10:.1f}", "count": count}
            for i, count in enumerate(bins)
        ],
        "topSources": [{"ip": ip, "count": count} for ip, count in sources.most_common(10)],
    }


def summarize_http_log(path: Path | None) -> dict[str, Any]:
    result = {
        "path": str(path) if path else "",
        "rows": 0,
        "success": 0,
        "failed": 0,
        "statusCounts": {},
        "errors": {},
        "timeline": [],
    }
    if not path or not path.exists():
        return result
    rows = read_csv_dicts(path)
    status_counts: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    by_second: dict[str, dict[str, int]] = defaultdict(lambda: {"success": 0, "failed": 0})
    for row in rows:
        status = (row.get("status_code") or row.get("status") or "unknown").strip()
        status_counts[status] += 1
        error = (row.get("error") or "").strip()
        timestamp = (row.get("timestamp") or "")[:19]
        ok = status.startswith("2") and not error
        if ok:
            result["success"] += 1
            by_second[timestamp]["success"] += 1
        else:
            result["failed"] += 1
            by_second[timestamp]["failed"] += 1
            if error:
                errors[error.split(":")[0]] += 1
    ordered_times = sorted(by_second.keys(), key=lambda value: parse_timestamp(value) or datetime.min)
    result.update(
        {
            "rows": len(rows),
            "statusCounts": dict(status_counts),
            "errors": dict(errors.most_common(6)),
            "timeline": [
                {
                    "t": timestamp,
                    "x": idx,
                    "success": by_second[timestamp]["success"],
                    "failed": by_second[timestamp]["failed"],
                }
                for idx, timestamp in enumerate(ordered_times)
            ],
        }
    )
    return result


def count_attack_log(path: Path | None, action_name: str) -> dict[str, Any]:
    result = {"path": str(path) if path else "", "rows": 0, "action": action_name, "timeline": []}
    if not path or not path.exists():
        return result
    rows = read_csv_dicts(path)
    by_second: Counter[str] = Counter()
    for row in rows:
        timestamp = (row.get("timestamp") or "")[:19]
        by_second[timestamp] += 1
    ordered_times = sorted(by_second.keys(), key=lambda value: parse_timestamp(value) or datetime.min)
    result["rows"] = len(rows)
    result["timeline"] = [
        {"t": timestamp, "x": idx, "count": by_second[timestamp]}
        for idx, timestamp in enumerate(ordered_times)
    ]
    return result


def pct_reduction(before: float, after: float) -> float:
    if before <= 0:
        return 0.0
    return round(max(0.0, (before - after) / before * 100), 1)


def collect_data(root: Path, run_id: str, title: str) -> dict[str, Any]:
    feature_dir = root / "data" / "features" / run_id
    log_dir = root / "data" / "logs" / run_id
    pcap_dir = root / "data" / "pcap" / run_id

    phases: dict[str, Any] = {}
    for key, meta in PHASES.items():
        csv_path = pick_file(feature_dir, meta["csv_prefixes"], ".csv")
        pcap_path = pick_file(pcap_dir, meta["pcap_prefixes"], ".pcap")
        tcpdump_path = pick_file(log_dir, (meta["tcpdump_prefix"],), ".log")
        features = summarize_features(csv_path, meta["label"])
        features["summary"]["tone"] = meta["tone"]
        features["pcap"] = file_size_stats(pcap_path)
        features["tcpdump"] = parse_tcpdump_log(tcpdump_path)
        phases[key] = features

    decision_path = pick_file(log_dir, ("decision_", "decision"), ".json")
    before = phases["before"]
    after = phases["after"]
    computed = {
        "packetReductionPct": pct_reduction(
            before["tcpdump"]["captured"], after["tcpdump"]["captured"]
        ),
        "pcapReductionPct": pct_reduction(before["pcap"]["bytes"], after["pcap"]["bytes"]),
        "peakPpsReductionPct": pct_reduction(
            before["summary"]["maxPps"], after["summary"]["maxPps"]
        ),
        "avgPpsReductionPct": pct_reduction(
            before["summary"]["avgPps"], after["summary"]["avgPps"]
        ),
    }

    return {
        "title": title,
        "runId": run_id,
        "generatedAt": datetime.now().astimezone().isoformat(timespec="seconds"),
        "directories": {
            "features": str(feature_dir),
            "logs": str(log_dir),
            "pcap": str(pcap_dir),
        },
        "phases": phases,
        "decision": summarize_decisions(decision_path),
        "http": summarize_http_log(log_dir / "http_flood.log"),
        "syn": count_attack_log(log_dir / "syn_flood.log", "SYN"),
        "udp": count_attack_log(log_dir / "udp_reflection.log", "UDP"),
        "computed": computed,
    }


def render_html(data: dict[str, Any]) -> str:
    json_data = json.dumps(data, ensure_ascii=False)
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{data["title"]} - {data["runId"]}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --surface: #ffffff;
      --ink: #172033;
      --muted: #667085;
      --line: #d7dce4;
      --blue: #1d5fd1;
      --teal: #0e9384;
      --red: #d92d20;
      --amber: #b54708;
      --green: #039855;
      --shadow: 0 10px 24px rgba(23, 32, 51, 0.08);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: Inter, "Segoe UI", "Microsoft YaHei", Arial, sans-serif;
      letter-spacing: 0;
    }}
    .topbar {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 18px;
      padding: 22px 32px;
      background: #ffffff;
      border-bottom: 1px solid var(--line);
      position: sticky;
      top: 0;
      z-index: 4;
    }}
    .title {{
      display: flex;
      flex-direction: column;
      gap: 4px;
      min-width: 0;
    }}
    h1 {{
      margin: 0;
      font-size: 24px;
      line-height: 1.2;
      font-weight: 760;
    }}
    .run-meta {{
      color: var(--muted);
      font-size: 13px;
      overflow-wrap: anywhere;
    }}
    main {{
      max-width: 1320px;
      margin: 0 auto;
      padding: 24px 28px 36px;
    }}
    section {{
      margin: 0 0 22px;
    }}
    .kpis {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
    }}
    .card {{
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      padding: 16px;
      min-width: 0;
    }}
    .kpi-label {{
      color: var(--muted);
      font-size: 13px;
      line-height: 1.35;
      margin-bottom: 8px;
    }}
    .kpi-value {{
      font-size: 30px;
      line-height: 1;
      font-weight: 800;
      white-space: nowrap;
    }}
    .kpi-sub {{
      margin-top: 8px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.4;
      overflow-wrap: anywhere;
    }}
    .ok {{ color: var(--green); }}
    .danger {{ color: var(--red); }}
    .shield {{ color: var(--teal); }}
    .amber {{ color: var(--amber); }}
    .grid-two {{
      display: grid;
      grid-template-columns: minmax(0, 1.35fr) minmax(330px, 0.65fr);
      gap: 16px;
    }}
    .section-title {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 12px;
    }}
    h2 {{
      margin: 0;
      font-size: 17px;
      line-height: 1.2;
    }}
    .segmented {{
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 4px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #eef2f6;
    }}
    .segmented button {{
      border: 0;
      border-radius: 6px;
      padding: 8px 10px;
      background: transparent;
      color: var(--muted);
      font-weight: 650;
      min-width: 70px;
      cursor: pointer;
    }}
    .segmented button.active {{
      background: var(--surface);
      color: var(--ink);
      box-shadow: 0 1px 4px rgba(23, 32, 51, 0.12);
    }}
    .chart {{
      width: 100%;
      min-height: 340px;
    }}
    svg {{
      display: block;
      width: 100%;
      height: auto;
      overflow: visible;
    }}
    .timeline {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
    }}
    .phase {{
      border-left: 5px solid var(--blue);
    }}
    .phase.ok {{ border-color: var(--green); }}
    .phase.danger {{ border-color: var(--red); }}
    .phase.shield {{ border-color: var(--teal); }}
    .phase.amber {{ border-color: var(--amber); }}
    .phase-name {{
      font-size: 15px;
      font-weight: 760;
      margin-bottom: 10px;
    }}
    .phase-line {{
      display: flex;
      justify-content: space-between;
      gap: 10px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.55;
      border-top: 1px solid #eef1f5;
      padding-top: 7px;
      margin-top: 7px;
    }}
    .phase-line strong {{
      color: var(--ink);
      font-weight: 760;
      text-align: right;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}
    th, td {{
      padding: 11px 10px;
      border-bottom: 1px solid #edf0f5;
      text-align: right;
      white-space: nowrap;
    }}
    th:first-child, td:first-child {{
      text-align: left;
    }}
    th {{
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
    }}
    .mini-list {{
      display: grid;
      gap: 9px;
    }}
    .mini-row {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding-bottom: 8px;
      border-bottom: 1px solid #edf0f5;
      font-size: 13px;
    }}
    .mini-row span:first-child {{
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: var(--muted);
    }}
    .mini-row strong {{
      white-space: nowrap;
    }}
    .speaker {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
    }}
    .speaker .card {{
      box-shadow: none;
    }}
    .note-number {{
      width: 26px;
      height: 26px;
      border-radius: 50%;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      background: #e7eefc;
      color: var(--blue);
      font-weight: 800;
      margin-bottom: 10px;
    }}
    .note-title {{
      font-weight: 760;
      margin-bottom: 6px;
    }}
    .note-text {{
      color: var(--muted);
      font-size: 13px;
      line-height: 1.55;
    }}
    .footer {{
      color: var(--muted);
      font-size: 12px;
      line-height: 1.6;
      overflow-wrap: anywhere;
    }}
    @media (max-width: 980px) {{
      .kpis, .timeline, .speaker, .grid-two {{
        grid-template-columns: 1fr;
      }}
      .topbar {{
        align-items: flex-start;
        flex-direction: column;
        padding: 18px;
      }}
      main {{
        padding: 18px;
      }}
      .section-title {{
        align-items: flex-start;
        flex-direction: column;
      }}
      th, td {{
        white-space: normal;
      }}
      .kpi-value {{
        font-size: 26px;
      }}
    }}
  </style>
</head>
<body>
  <header class="topbar">
    <div class="title">
      <h1>{data["title"]}</h1>
      <div class="run-meta">Run ID: <strong>{data["runId"]}</strong> · 生成时间: {data["generatedAt"]}</div>
    </div>
    <div class="run-meta">数据来源: data/features · data/logs · data/pcap</div>
  </header>

  <main>
    <section class="kpis" id="kpis"></section>

    <section class="timeline" id="timeline"></section>

    <section class="grid-two">
      <div class="card">
        <div class="section-title">
          <h2>流量时间线</h2>
          <div class="segmented" id="metricButtons">
            <button type="button" data-metric="pps" class="active">PPS</button>
            <button type="button" data-metric="mbps">Mbps</button>
            <button type="button" data-metric="syn">SYN</button>
            <button type="button" data-metric="unique">源 IP</button>
          </div>
        </div>
        <div class="chart"><svg id="trafficChart" viewBox="0 0 980 340" role="img" aria-label="Traffic timeline chart"></svg></div>
      </div>
      <div class="card">
        <div class="section-title"><h2>模型决策</h2></div>
        <div class="chart"><svg id="decisionChart" viewBox="0 0 420 340" role="img" aria-label="Decision confidence histogram"></svg></div>
      </div>
    </section>

    <section class="grid-two">
      <div class="card">
        <div class="section-title"><h2>阶段对比</h2></div>
        <div id="phaseTable"></div>
      </div>
      <div class="card">
        <div class="section-title"><h2>攻击请求结果</h2></div>
        <div class="chart"><svg id="httpChart" viewBox="0 0 420 290" role="img" aria-label="HTTP flood status chart"></svg></div>
        <div class="mini-list" id="attackLogList"></div>
      </div>
    </section>

    <section class="speaker" id="speakerNotes"></section>

    <section class="footer card" id="filePaths"></section>
  </main>

  <script>
    const DEMO = {json_data};
    const PHASE_ORDER = [
      ["normal", "正常流量", "#039855"],
      ["before", "攻击前", "#d92d20"],
      ["after", "防御后", "#0e9384"],
    ];
    const METRIC_LABELS = {{
      pps: "Packets per second",
      mbps: "Mbps",
      syn: "SYN packets",
      unique: "Unique source IPs",
    }};

    function fmt(value, digits = 0) {{
      const n = Number(value || 0);
      if (Math.abs(n) >= 1000000) return (n / 1000000).toFixed(2) + "M";
      if (Math.abs(n) >= 1000) return (n / 1000).toFixed(1) + "K";
      return n.toLocaleString(undefined, {{ maximumFractionDigits: digits }});
    }}

    function pct(value) {{
      return Number(value || 0).toFixed(1) + "%";
    }}

    function setHTML(id, html) {{
      document.getElementById(id).innerHTML = html;
    }}

    function kpis() {{
      const normal = DEMO.phases.normal;
      const before = DEMO.phases.before;
      const after = DEMO.phases.after;
      const decision = DEMO.decision;
      setHTML("kpis", `
        <div class="card">
          <div class="kpi-label">正常访问</div>
          <div class="kpi-value ok">${{fmt(normal.summary.maxPps)}} PPS</div>
          <div class="kpi-sub">HTTP 正常阶段全部用于建立基线</div>
        </div>
        <div class="card">
          <div class="kpi-label">攻击峰值</div>
          <div class="kpi-value danger">${{fmt(before.summary.maxPps)}} PPS</div>
          <div class="kpi-sub">攻击前抓包 ${{fmt(before.tcpdump.captured)}} packets</div>
        </div>
        <div class="card">
          <div class="kpi-label">模型判定</div>
          <div class="kpi-value amber">${{fmt(decision.count)}} 条</div>
          <div class="kpi-sub">平均置信度 ${{Number(decision.confidence.avg || 0).toFixed(3)}}，阈值 ${{decision.threshold}}</div>
        </div>
        <div class="card">
          <div class="kpi-label">防御后下降</div>
          <div class="kpi-value shield">${{pct(DEMO.computed.packetReductionPct)}}</div>
          <div class="kpi-sub">防御后抓包 ${{fmt(after.tcpdump.captured)}} packets</div>
        </div>
      `);
    }}

    function timeline() {{
      const decision = DEMO.decision;
      const items = [
        ["ok", "1", "正常流量", [
          ["CSV 行数", DEMO.phases.normal.summary.rows],
          ["抓包大小", DEMO.phases.normal.pcap.mb + " MB"],
          ["峰值 PPS", fmt(DEMO.phases.normal.summary.maxPps)],
        ]],
        ["danger", "2", "攻击爆发", [
          ["CSV 行数", DEMO.phases.before.summary.rows],
          ["抓包大小", DEMO.phases.before.pcap.mb + " MB"],
          ["峰值 PPS", fmt(DEMO.phases.before.summary.maxPps)],
        ]],
        ["amber", "3", "模型识别", [
          ["判定数量", fmt(decision.count)],
          ["动作", Object.keys(decision.actions || {{}}).join(", ") || "-"],
          ["最高置信度", Number(decision.confidence.max || 0).toFixed(3)],
        ]],
        ["shield", "4", "防御生效", [
          ["抓包下降", pct(DEMO.computed.pcapReductionPct)],
          ["包数下降", pct(DEMO.computed.packetReductionPct)],
          ["峰值下降", pct(DEMO.computed.peakPpsReductionPct)],
        ]],
      ];
      setHTML("timeline", items.map(([tone, step, title, rows]) => `
        <div class="card phase ${{tone}}">
          <div class="phase-name">${{step}}. ${{title}}</div>
          ${{rows.map(([name, value]) => `<div class="phase-line"><span>${{name}}</span><strong>${{value}}</strong></div>`).join("")}}
        </div>
      `).join(""));
    }}

    function allTrafficPoints(metric) {{
      const gap = 5;
      let offset = 0;
      const series = [];
      PHASE_ORDER.forEach(([key, label, color]) => {{
        const points = (DEMO.phases[key].timeline || []).map((point, idx) => ({{
          x: offset + idx,
          y: Number(point[metric] || 0),
        }}));
        series.push({{ key, label, color, points, start: offset, end: offset + Math.max(0, points.length - 1) }});
        offset += Math.max(1, points.length) + gap;
      }});
      return series;
    }}

    function linePath(points, xScale, yScale) {{
      return points.map((point, idx) => `${{idx === 0 ? "M" : "L"}} ${{xScale(point.x).toFixed(1)}} ${{yScale(point.y).toFixed(1)}}`).join(" ");
    }}

    function drawTraffic(metric = "pps") {{
      const svg = document.getElementById("trafficChart");
      const width = 980, height = 340;
      const pad = {{ left: 68, right: 24, top: 26, bottom: 56 }};
      const chartW = width - pad.left - pad.right;
      const chartH = height - pad.top - pad.bottom;
      const series = allTrafficPoints(metric);
      const all = series.flatMap(s => s.points);
      const maxX = Math.max(1, ...all.map(p => p.x));
      const maxY = Math.max(1, ...all.map(p => p.y));
      const niceY = maxY * 1.08;
      const xScale = x => pad.left + (x / maxX) * chartW;
      const yScale = y => pad.top + chartH - (y / niceY) * chartH;
      const grid = [];
      for (let i = 0; i <= 4; i++) {{
        const y = pad.top + chartH * i / 4;
        const value = niceY * (1 - i / 4);
        grid.push(`<line x1="${{pad.left}}" y1="${{y}}" x2="${{width - pad.right}}" y2="${{y}}" stroke="#e8ecf2"/>`);
        grid.push(`<text x="${{pad.left - 10}}" y="${{y + 4}}" text-anchor="end" font-size="12" fill="#667085">${{fmt(value, 2)}}</text>`);
      }}
      const phaseLabels = series.map(s => {{
        const mid = (s.start + s.end) / 2;
        return `<text x="${{xScale(mid)}}" y="${{height - 18}}" text-anchor="middle" font-size="13" font-weight="700" fill="${{s.color}}">${{s.label}}</text>`;
      }}).join("");
      const lines = series.map(s => {{
        if (!s.points.length) return "";
        return `
          <path d="${{linePath(s.points, xScale, yScale)}}" fill="none" stroke="${{s.color}}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
          ${{s.points.map((p, i) => i % Math.ceil(Math.max(1, s.points.length / 10)) === 0 ? `<circle cx="${{xScale(p.x)}}" cy="${{yScale(p.y)}}" r="3.5" fill="${{s.color}}"/>` : "").join("")}}
        `;
      }}).join("");
      svg.innerHTML = `
        <rect x="0" y="0" width="${{width}}" height="${{height}}" fill="#fff"/>
        <text x="${{pad.left}}" y="18" font-size="13" fill="#667085">${{METRIC_LABELS[metric]}}</text>
        ${{grid.join("")}}
        <line x1="${{pad.left}}" y1="${{pad.top + chartH}}" x2="${{width - pad.right}}" y2="${{pad.top + chartH}}" stroke="#b9c1cf"/>
        <line x1="${{pad.left}}" y1="${{pad.top}}" x2="${{pad.left}}" y2="${{pad.top + chartH}}" stroke="#b9c1cf"/>
        ${{lines}}
        ${{phaseLabels}}
      `;
    }}

    function drawDecision() {{
      const svg = document.getElementById("decisionChart");
      const data = DEMO.decision.histogram || [];
      const width = 420, height = 340;
      const pad = {{ left: 42, right: 18, top: 20, bottom: 62 }};
      const chartW = width - pad.left - pad.right;
      const chartH = height - pad.top - pad.bottom;
      const maxY = Math.max(1, ...data.map(d => d.count));
      const barGap = 5;
      const barW = chartW / Math.max(1, data.length) - barGap;
      const bars = data.map((d, i) => {{
        const h = (d.count / maxY) * chartH;
        const x = pad.left + i * (barW + barGap);
        const y = pad.top + chartH - h;
        const active = d.count > 0;
        return `
          <rect x="${{x}}" y="${{y}}" width="${{barW}}" height="${{h}}" rx="3" fill="${{active ? "#1d5fd1" : "#d7dce4"}}"/>
          <text x="${{x + barW / 2}}" y="${{height - 36}}" text-anchor="middle" font-size="10" fill="#667085" transform="rotate(-35 ${{x + barW / 2}} ${{height - 36}})">${{d.label}}</text>
          ${{active ? `<text x="${{x + barW / 2}}" y="${{Math.max(14, y - 5)}}" text-anchor="middle" font-size="11" fill="#172033">${{d.count}}</text>` : ""}}
        `;
      }}).join("");
      svg.innerHTML = `
        <rect x="0" y="0" width="${{width}}" height="${{height}}" fill="#fff"/>
        <text x="${{pad.left}}" y="16" font-size="13" fill="#667085">Confidence distribution</text>
        <line x1="${{pad.left}}" y1="${{pad.top + chartH}}" x2="${{width - pad.right}}" y2="${{pad.top + chartH}}" stroke="#b9c1cf"/>
        <line x1="${{pad.left}}" y1="${{pad.top}}" x2="${{pad.left}}" y2="${{pad.top + chartH}}" stroke="#b9c1cf"/>
        ${{bars}}
      `;
    }}

    function drawHttp() {{
      const svg = document.getElementById("httpChart");
      const width = 420, height = 290;
      const success = Number(DEMO.http.success || 0);
      const failed = Number(DEMO.http.failed || 0);
      const total = Math.max(1, success + failed);
      const successW = 300 * success / total;
      const failedW = 300 * failed / total;
      svg.innerHTML = `
        <rect x="0" y="0" width="${{width}}" height="${{height}}" fill="#fff"/>
        <text x="24" y="30" font-size="13" fill="#667085">HTTP flood requests</text>
        <rect x="60" y="72" width="${{successW}}" height="44" rx="5" fill="#039855"/>
        <rect x="${{60 + successW}}" y="72" width="${{failedW}}" height="44" rx="5" fill="#d92d20"/>
        <text x="60" y="148" font-size="13" fill="#172033">成功 ${{fmt(success)}} · 失败/超时 ${{fmt(failed)}}</text>
        <text x="60" y="178" font-size="13" fill="#667085">成功率 ${{(success / total * 100).toFixed(1)}}%</text>
        <text x="60" y="218" font-size="12" fill="#667085">SYN log rows: ${{fmt(DEMO.syn.rows)}} · UDP log rows: ${{fmt(DEMO.udp.rows)}}</text>
      `;
      const errors = Object.entries(DEMO.http.errors || {{}}).map(([name, count]) =>
        `<div class="mini-row"><span>${{name}}</span><strong>${{fmt(count)}}</strong></div>`
      ).join("");
      setHTML("attackLogList", errors || `<div class="mini-row"><span>HTTP error</span><strong>0</strong></div>`);
    }}

    function phaseTable() {{
      const rows = PHASE_ORDER.map(([key, label]) => {{
        const phase = DEMO.phases[key];
        return `
          <tr>
            <td><strong>${{label}}</strong></td>
            <td>${{fmt(phase.summary.rows)}}</td>
            <td>${{fmt(phase.tcpdump.captured)}}</td>
            <td>${{phase.pcap.mb}} MB</td>
            <td>${{fmt(phase.summary.maxPps)}}</td>
            <td>${{fmt(phase.summary.avgPps, 1)}}</td>
            <td>${{fmt(phase.summary.maxSyn)}}</td>
            <td>${{fmt(phase.summary.maxUniqueSrc)}}</td>
          </tr>
        `;
      }}).join("");
      setHTML("phaseTable", `
        <table>
          <thead>
            <tr>
              <th>阶段</th>
              <th>CSV 行</th>
              <th>抓包数</th>
              <th>PCAP</th>
              <th>峰值 PPS</th>
              <th>平均 PPS</th>
              <th>峰值 SYN</th>
              <th>源 IP 峰值</th>
            </tr>
          </thead>
          <tbody>${{rows}}</tbody>
        </table>
      `);
    }}

    function notes() {{
      const items = [
        ["建立基线", "先展示正常阶段：服务可访问，PPS 和源 IP 数都保持低位。"],
        ["发动攻击", "切到攻击前：抓包数、PPS、SYN/UDP 行数明显抬升，目标服务开始承压。"],
        ["模型决策", "查看决策数量和置信度：超过阈值的源地址被标记为 attack/block。"],
        ["验证防御", "对比防御后：PCAP 大小、抓包数、峰值 PPS 下降，说明规则生效。"],
      ];
      setHTML("speakerNotes", items.map((item, idx) => `
        <div class="card">
          <div class="note-number">${{idx + 1}}</div>
          <div class="note-title">${{item[0]}}</div>
          <div class="note-text">${{item[1]}}</div>
        </div>
      `).join(""));
    }}

    function paths() {{
      setHTML("filePaths", `
        <strong>文件位置</strong><br>
        Features: ${{DEMO.directories.features}}<br>
        Logs: ${{DEMO.directories.logs}}<br>
        PCAP: ${{DEMO.directories.pcap}}<br>
        Decision: ${{DEMO.decision.path || "-"}}
      `);
    }}

    document.querySelectorAll("#metricButtons button").forEach(button => {{
      button.addEventListener("click", () => {{
        document.querySelectorAll("#metricButtons button").forEach(item => item.classList.remove("active"));
        button.classList.add("active");
        drawTraffic(button.dataset.metric);
      }});
    }});

    kpis();
    timeline();
    drawTraffic("pps");
    drawDecision();
    drawHttp();
    phaseTable();
    notes();
    paths();
  </script>
</body>
</html>
"""


def main() -> None:
    args = parse_args()
    root = Path.cwd()
    run_id = args.run_id or latest_complete_run(root)
    output = (
        Path(args.output)
        if args.output
        else root / "data" / "logs" / run_id / f"demo_visualization_{run_id}.html"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    data = collect_data(root, run_id, args.title)
    output.write_text(render_html(data), encoding="utf-8")
    print(f"Generated visualization: {output}")


if __name__ == "__main__":
    main()
