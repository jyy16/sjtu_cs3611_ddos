#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate an offline dashboard for a realtime Project 9 DDoS defense run."""

from __future__ import annotations

import argparse
import csv
import html
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from statistics import mean
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate an offline HTML dashboard for a realtime Project 9 DDoS demo run."
    )
    parser.add_argument(
        "--run-id",
        help="Run id under data/features, data/logs, and data/pcap. Defaults to the latest realtime run.",
    )
    parser.add_argument(
        "--output",
        help="Output HTML path. Defaults to data/logs/<run-id>/realtime_visualization_<run-id>.html.",
    )
    parser.add_argument(
        "--title",
        default="DDoS 实时攻防演示",
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


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            return parsed.astimezone()
        return parsed
    except ValueError:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text[:19], fmt)
        except ValueError:
            continue
    return None


def format_dt(value: datetime | None) -> str:
    if value is None:
        return ""
    return value.isoformat(timespec="seconds")


def seconds_between(start: datetime | None, end: datetime | None) -> float:
    if start is None or end is None:
        return 0.0
    return max(0.0, (end - start).total_seconds())


def latest_realtime_run(root: Path) -> str:
    feature_root = root / "data" / "features"
    candidates: list[Path] = []
    if feature_root.exists():
        candidates = sorted(
            (p for p in feature_root.iterdir() if p.is_dir()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
    for candidate in candidates:
        if any(candidate.glob("attack_realtime_defense_*.csv")):
            return candidate.name
        if (candidate / "realtime_windows").exists():
            return candidate.name
    raise SystemExit("No realtime run directory found under data/features.")


def pick_file(directory: Path, prefixes: tuple[str, ...], suffix: str) -> Path | None:
    if not directory.exists():
        return None
    matches: list[Path] = []
    for prefix in prefixes:
        matches.extend(directory.glob(f"{prefix}*{suffix}"))
    if not matches:
        return None
    return sorted(set(matches), key=lambda path: (len(path.name), path.name))[0]


def read_csv_dicts(path: Path | None) -> list[dict[str, str]]:
    if not path or not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def summarize_features(path: Path | None, label: str) -> dict[str, Any]:
    rows = read_csv_dicts(path)
    by_time: dict[str, dict[str, float]] = defaultdict(
        lambda: {"pps": 0.0, "bps": 0.0, "syn": 0.0, "ack": 0.0, "unique": 0.0}
    )
    protocols = Counter()
    top_sources: Counter[str] = Counter()
    source_pps: Counter[str] = Counter()

    for row in rows:
        timestamp = row.get("timestamp", "")
        src_ip = row.get("src_ip", "unknown") or "unknown"
        protocols[row.get("protocol", "UNKNOWN") or "UNKNOWN"] += 1
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
            "mbps": round(by_time[timestamp]["bps"] / 1_000_000, 6),
            "syn": round(by_time[timestamp]["syn"], 3),
            "ack": round(by_time[timestamp]["ack"], 3),
            "unique": round(by_time[timestamp]["unique"], 3),
        }
        for idx, timestamp in enumerate(ordered_times)
    ]

    def values(key: str) -> list[float]:
        return [safe_float(point.get(key)) for point in timeline]

    return {
        "label": label,
        "path": str(path) if path else "",
        "rows": len(rows),
        "windows": len(timeline),
        "protocols": dict(protocols),
        "avgPps": round(mean(values("pps")), 3) if timeline else 0,
        "maxPps": round(max(values("pps")), 3) if timeline else 0,
        "avgMbps": round(mean(values("mbps")), 6) if timeline else 0,
        "maxMbps": round(max(values("mbps")), 6) if timeline else 0,
        "maxSyn": round(max(values("syn")), 3) if timeline else 0,
        "maxUniqueSrc": round(max(values("unique")), 3) if timeline else 0,
        "topSources": [
            {"ip": ip, "rows": count, "pps": round(source_pps[ip], 3)}
            for ip, count in top_sources.most_common(8)
        ],
        "timeline": timeline,
    }


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


def window_index(value: str) -> str:
    match = re.search(r"window_(\d+)", value)
    return match.group(1) if match else ""


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def decision_files(log_dir: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for path in sorted((log_dir / "realtime_decisions").glob("decision_window_*.json")):
        idx = window_index(path.name)
        if idx:
            result[idx] = path
    return result


def summarize_decisions(log_dir: Path, run_id: str) -> dict[str, Any]:
    combined_path = log_dir / f"decision_realtime_{run_id}.json"
    payload = load_json(combined_path) if combined_path.exists() else {}
    all_window_decisions = payload.get("all_window_decisions")
    decisions = payload.get("decisions")

    if not isinstance(all_window_decisions, list):
        all_window_decisions = []
        for path in sorted((log_dir / "realtime_decisions").glob("decision_window_*.json")):
            item_payload = load_json(path)
            for decision in item_payload.get("decisions", []):
                if isinstance(decision, dict):
                    enriched = dict(decision)
                    enriched["window"] = path.stem
                    enriched["decision_path"] = str(path)
                    all_window_decisions.append(enriched)

    if not isinstance(decisions, list):
        best: dict[tuple[str, str], dict[str, Any]] = {}
        for decision in all_window_decisions:
            if not isinstance(decision, dict):
                continue
            key = (str(decision.get("src_ip", "")), str(decision.get("action", "")))
            confidence = safe_float(decision.get("confidence"))
            if key not in best or confidence > safe_float(best[key].get("confidence")):
                best[key] = decision
        decisions = list(best.values())

    confidences = [safe_float(item.get("confidence")) for item in all_window_decisions if isinstance(item, dict)]
    bins = [0] * 10
    for confidence in confidences:
        idx = min(9, max(0, int(math.floor(confidence * 10))))
        bins[idx] += 1

    per_window: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"decisions": 0, "maxConfidence": 0.0, "sources": Counter()}
    )
    for decision in all_window_decisions:
        if not isinstance(decision, dict):
            continue
        idx = window_index(str(decision.get("window") or decision.get("decision_path") or ""))
        if not idx:
            continue
        confidence = safe_float(decision.get("confidence"))
        per_window[idx]["decisions"] += 1
        per_window[idx]["maxConfidence"] = max(per_window[idx]["maxConfidence"], confidence)
        per_window[idx]["sources"][str(decision.get("src_ip", "unknown"))] += 1

    return {
        "path": str(combined_path) if combined_path.exists() else "",
        "generatedAt": payload.get("generated_at", ""),
        "threshold": safe_float(payload.get("threshold"), 0.8),
        "dedupedCount": len(decisions),
        "windowDecisionCount": len(all_window_decisions),
        "confidence": {
            "min": round(min(confidences), 6) if confidences else 0,
            "max": round(max(confidences), 6) if confidences else 0,
            "avg": round(mean(confidences), 6) if confidences else 0,
        },
        "histogram": [
            {"label": f"{i / 10:.1f}-{(i + 1) / 10:.1f}", "count": count}
            for i, count in enumerate(bins)
        ],
        "topSources": [
            {"ip": ip, "count": count}
            for ip, count in Counter(
                str(item.get("src_ip", "unknown"))
                for item in all_window_decisions
                if isinstance(item, dict)
            ).most_common(10)
        ],
        "perWindow": {
            idx: {
                "decisions": value["decisions"],
                "maxConfidence": round(value["maxConfidence"], 6),
                "topSource": value["sources"].most_common(1)[0][0] if value["sources"] else "",
            }
            for idx, value in per_window.items()
        },
    }


def parse_defense_actions(log_dir: Path) -> list[dict[str, Any]]:
    path = log_dir / "defense_blocks.log"
    if not path.exists():
        return []
    actions: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        parts = line.split(",")
        item: dict[str, Any] = {"timestamp": parts[0], "_dt": parse_timestamp(parts[0])}
        for part in parts[1:]:
            key, _, value = part.partition("=")
            if key:
                item[key] = value
        actions.append(item)
    return actions


def read_window_summary(log_dir: Path, run_id: str) -> dict[str, dict[str, str]]:
    path = log_dir / f"realtime_window_summary_{run_id}.csv"
    rows = read_csv_dicts(path)
    return {row.get("window", ""): row for row in rows if row.get("window")}


def assign_actions_to_windows(
    windows: list[dict[str, Any]],
    actions: list[dict[str, Any]],
) -> None:
    ordered = sorted(
        (window for window in windows if window.get("_decisionDt")),
        key=lambda window: window["_decisionDt"],
    )
    for pos, window in enumerate(ordered):
        start = window["_decisionDt"]
        next_start = ordered[pos + 1]["_decisionDt"] if pos + 1 < len(ordered) else None
        matched = []
        for action in actions:
            action_dt = action.get("_dt")
            if action_dt is None or action_dt < start:
                continue
            if next_start is not None and action_dt >= next_start:
                continue
            matched.append(action)
        window["_actions"] = matched


def collect_windows(
    feature_dir: Path,
    log_dir: Path,
    run_id: str,
    decision: dict[str, Any],
    actions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    summary = read_window_summary(log_dir, run_id)
    csv_by_index: dict[str, Path] = {}
    window_dir = feature_dir / "realtime_windows"
    for path in sorted(window_dir.glob("window_*.csv")):
        idx = window_index(path.name)
        if idx:
            csv_by_index[idx] = path

    decisions_by_index = decision_files(log_dir)
    indexes = sorted(set(summary) | set(csv_by_index) | set(decisions_by_index), key=lambda value: int(value))
    windows: list[dict[str, Any]] = []
    for idx in indexes:
        feature_summary = summarize_features(csv_by_index.get(idx), f"窗口 {idx}")
        decision_info = decision["perWindow"].get(idx, {})
        summary_row = summary.get(idx, {})
        capture_start = parse_timestamp(summary_row.get("capture_started_at"))
        capture_seconds = safe_float(summary_row.get("capture_seconds"))
        capture_end = capture_start + timedelta(seconds=capture_seconds) if capture_start else None
        decision_payload = load_json(decisions_by_index[idx]) if idx in decisions_by_index else {}
        decision_dt = parse_timestamp(decision_payload.get("generated_at"))

        windows.append(
            {
                "index": idx,
                "captureStartedAt": format_dt(capture_start),
                "captureEndedAt": format_dt(capture_end),
                "captureSeconds": round(capture_seconds, 3),
                "decisionGeneratedAt": format_dt(decision_dt),
                "decisionLatencySec": round(seconds_between(capture_start, decision_dt), 3),
                "rows": feature_summary["rows"],
                "maxPps": feature_summary["maxPps"],
                "maxMbps": feature_summary["maxMbps"],
                "maxSyn": feature_summary["maxSyn"],
                "decisions": decision_info.get("decisions", 0),
                "maxConfidence": decision_info.get("maxConfidence", 0),
                "topSource": decision_info.get("topSource", ""),
                "extractStatus": summary_row.get("extract_status", ""),
                "inferStatus": summary_row.get("infer_status", ""),
                "applyStatus": summary_row.get("apply_status", ""),
                "csv": str(csv_by_index.get(idx, "")),
                "decision": str(decisions_by_index.get(idx, summary_row.get("decision", ""))),
                "_captureStart": capture_start,
                "_captureEnd": capture_end,
                "_decisionDt": decision_dt,
                "_actions": [],
            }
        )

    assign_actions_to_windows(windows, actions)
    for window in windows:
        matched = window.pop("_actions", [])
        first_action = min((action.get("_dt") for action in matched if action.get("_dt")), default=None)
        last_action = max((action.get("_dt") for action in matched if action.get("_dt")), default=None)
        window["actionCount"] = len(matched)
        window["firstActionAt"] = format_dt(first_action)
        window["lastActionAt"] = format_dt(last_action)
        window["firstActionLatencySec"] = round(seconds_between(window.pop("_captureStart"), first_action), 3)
        window["blockSpanSec"] = round(seconds_between(first_action, last_action), 3)
        window.pop("_captureEnd", None)
        window.pop("_decisionDt", None)

    return windows


def public_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for action in actions:
        item = {key: value for key, value in action.items() if not key.startswith("_")}
        result.append(item)
    return result


def collect_data(root: Path, run_id: str, title: str) -> dict[str, Any]:
    feature_dir = root / "data" / "features" / run_id
    log_dir = root / "data" / "logs" / run_id
    pcap_dir = root / "data" / "pcap" / run_id

    normal_csv = pick_file(feature_dir, ("normal_", "normal"), ".csv")
    attack_csv = pick_file(feature_dir, ("attack_realtime_defense_",), ".csv")
    normal_pcap = pick_file(pcap_dir, ("normal_", "normal"), ".pcap")
    attack_pcap = pick_file(pcap_dir, ("attack_realtime_defense_",), ".pcap")

    decision = summarize_decisions(log_dir, run_id)
    actions = parse_defense_actions(log_dir)
    windows = collect_windows(feature_dir, log_dir, run_id, decision, actions)
    normal = summarize_features(normal_csv, "正常基线")
    attack = summarize_features(attack_csv, "混合攻击 + 实时防御")

    return {
        "title": title,
        "runId": run_id,
        "generatedAt": datetime.now().astimezone().isoformat(timespec="seconds"),
        "directories": {
            "features": str(feature_dir),
            "logs": str(log_dir),
            "pcap": str(pcap_dir),
        },
        "normal": {
            "summary": normal,
            "pcap": file_size_stats(normal_pcap),
            "tcpdump": parse_tcpdump_log(pick_file(log_dir, ("tcpdump_normal",), ".log")),
        },
        "attack": {
            "summary": attack,
            "pcap": file_size_stats(attack_pcap),
            "tcpdump": parse_tcpdump_log(
                pick_file(log_dir, ("tcpdump_attack_realtime_defense",), ".log")
            ),
        },
        "decision": decision,
        "actions": public_actions(actions),
        "windows": windows,
    }


def render_html(data: dict[str, Any]) -> str:
    json_data = json.dumps(data, ensure_ascii=False)
    title = html.escape(data["title"])
    run_id = html.escape(data["runId"])
    template = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>__TITLE__ - __RUN_ID__</title>
  <style>
    :root {
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
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: Inter, "Segoe UI", "Microsoft YaHei", Arial, sans-serif;
      letter-spacing: 0;
    }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 18px;
      padding: 22px 32px;
      background: #fff;
      border-bottom: 1px solid var(--line);
      position: sticky;
      top: 0;
      z-index: 4;
    }
    h1 { margin: 0 0 4px; font-size: 24px; line-height: 1.2; }
    h2 { margin: 0; font-size: 17px; line-height: 1.2; }
    main { max-width: 1320px; margin: 0 auto; padding: 24px 28px 36px; }
    section { margin-bottom: 22px; }
    .meta { color: var(--muted); font-size: 13px; overflow-wrap: anywhere; }
    .grid-4 { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; }
    .grid-2 { display: grid; grid-template-columns: minmax(0, 1.15fr) minmax(380px, 0.85fr); gap: 16px; }
    .card {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      padding: 16px;
      min-width: 0;
    }
    .kpi-label { color: var(--muted); font-size: 13px; margin-bottom: 8px; }
    .kpi-value { font-size: 30px; line-height: 1; font-weight: 800; white-space: nowrap; }
    .kpi-sub { margin-top: 8px; color: var(--muted); font-size: 12px; line-height: 1.4; overflow-wrap: anywhere; }
    .ok { color: var(--green); }
    .danger { color: var(--red); }
    .shield { color: var(--teal); }
    .amber { color: var(--amber); }
    .section-title { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 12px; }
    .chart { width: 100%; min-height: 330px; }
    svg { display: block; width: 100%; height: auto; overflow: visible; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 10px 9px; border-bottom: 1px solid #edf0f5; text-align: right; white-space: nowrap; }
    th:first-child, td:first-child { text-align: left; }
    th { color: var(--muted); font-size: 12px; font-weight: 700; }
    .status-ok { color: var(--green); font-weight: 760; }
    .status-failed { color: var(--red); font-weight: 760; }
    .status-muted { color: var(--muted); }
    .mini-list { display: grid; gap: 9px; }
    .mini-row { display: flex; justify-content: space-between; gap: 12px; padding-bottom: 8px; border-bottom: 1px solid #edf0f5; font-size: 13px; }
    .mini-row span:first-child { color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .note {
      background: #f7f9fc;
      border: 1px solid #e5eaf1;
      border-radius: 8px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.55;
      padding: 12px 14px;
      margin-bottom: 12px;
    }
    .footer { color: var(--muted); font-size: 12px; line-height: 1.6; overflow-wrap: anywhere; }
    @media (max-width: 980px) {
      .grid-4, .grid-2 { grid-template-columns: 1fr; }
      .topbar { align-items: flex-start; flex-direction: column; padding: 18px; }
      main { padding: 18px; }
      th, td { white-space: normal; }
      .kpi-value { font-size: 26px; }
    }
  </style>
</head>
<body>
  <header class="topbar">
    <div>
      <h1>__TITLE__</h1>
      <div class="meta">Run ID: <strong>__RUN_ID__</strong> · 生成时间: <span id="generatedAt"></span></div>
    </div>
    <div class="meta">前台混合攻击 · 后台窗口推理 · 自动封禁</div>
  </header>

  <main>
    <section class="grid-4" id="kpis"></section>

    <section class="grid-2">
      <div class="card">
        <div class="section-title"><h2>总流量时间线</h2><span class="meta">正常基线与实时攻防 run 对比</span></div>
        <div class="chart"><svg id="trafficChart" viewBox="0 0 940 330" role="img" aria-label="Realtime traffic chart"></svg></div>
      </div>
      <div class="card">
        <div class="section-title"><h2>防御流水线</h2><span class="meta">窗口 = 后台防御的一次检测批次</span></div>
        <div class="note">每个窗口会在攻击仍运行时抓一小段包，然后提特征、模型推理、调用封禁脚本。这里重点看“首封延迟”和封禁动作是否落在攻击期间。</div>
        <div class="chart"><svg id="pipelineChart" viewBox="0 0 520 330" role="img" aria-label="Realtime defense pipeline"></svg></div>
      </div>
    </section>

    <section class="grid-2">
      <div class="card">
        <div class="section-title"><h2>窗口证据</h2></div>
        <div id="windowTable"></div>
      </div>
      <div class="card">
        <div class="section-title"><h2>封禁动作</h2></div>
        <div id="actionsList" class="mini-list"></div>
      </div>
    </section>

    <section class="grid-2">
      <div class="card">
        <div class="section-title"><h2>模型置信度</h2></div>
        <div class="chart"><svg id="decisionChart" viewBox="0 0 600 290" role="img" aria-label="Decision confidence histogram"></svg></div>
      </div>
      <div class="card">
        <div class="section-title"><h2>文件位置</h2></div>
        <div class="footer" id="filePaths"></div>
      </div>
    </section>
  </main>

  <script>
    const DATA = __DATA__;
    document.getElementById("generatedAt").textContent = DATA.generatedAt;

    function fmt(value, digits = 0) {
      const n = Number(value || 0);
      if (Math.abs(n) >= 1000000) return (n / 1000000).toFixed(2) + "M";
      if (Math.abs(n) >= 1000) return (n / 1000).toFixed(1) + "K";
      return n.toLocaleString(undefined, { maximumFractionDigits: digits });
    }

    function sec(value) {
      const n = Number(value || 0);
      return n.toFixed(n >= 10 ? 0 : 1) + "s";
    }

    function clock(value) {
      if (!value) return "-";
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return value;
      return date.toLocaleTimeString(undefined, { hour12: false });
    }

    function statusClass(value) {
      if (value === "ok") return "status-ok";
      if (value === "failed") return "status-failed";
      return "status-muted";
    }

    function setHTML(id, html) {
      document.getElementById(id).innerHTML = html;
    }

    function kpis() {
      const normal = DATA.normal.summary;
      const attack = DATA.attack.summary;
      const decision = DATA.decision;
      const firstWindow = (DATA.windows || []).find(item => Number(item.actionCount || 0) > 0) || {};
      setHTML("kpis", `
        <div class="card">
          <div class="kpi-label">正常基线峰值</div>
          <div class="kpi-value ok">${fmt(normal.maxPps)} PPS</div>
          <div class="kpi-sub">正常阶段抓包 ${fmt(DATA.normal.tcpdump.captured)} packets</div>
        </div>
        <div class="card">
          <div class="kpi-label">攻防同时峰值</div>
          <div class="kpi-value danger">${fmt(attack.maxPps)} PPS</div>
          <div class="kpi-sub">攻击期间总抓包 ${fmt(DATA.attack.tcpdump.captured)} packets</div>
        </div>
        <div class="card">
          <div class="kpi-label">模型窗口决策</div>
          <div class="kpi-value amber">${fmt(decision.windowDecisionCount)} 条</div>
          <div class="kpi-sub">${fmt(DATA.windows.length)} 个窗口，最高置信度 ${Number(decision.confidence.max || 0).toFixed(3)}</div>
        </div>
        <div class="card">
          <div class="kpi-label">首封延迟</div>
          <div class="kpi-value shield">${firstWindow.firstActionAt ? sec(firstWindow.firstActionLatencySec) : "-"}</div>
          <div class="kpi-sub">${firstWindow.firstActionAt ? "首封时间 " + clock(firstWindow.firstActionAt) : "未记录封禁动作"}</div>
        </div>
      `);
    }

    function combinedSeries() {
      const gap = 5;
      let offset = 0;
      return [
        ["正常基线", "#039855", DATA.normal.summary.timeline || []],
        ["混合攻击 + 实时防御", "#d92d20", DATA.attack.summary.timeline || []],
      ].map(([label, color, source]) => {
        const points = source.map((point, idx) => ({ x: offset + idx, y: Number(point.pps || 0) }));
        const start = offset;
        const end = offset + Math.max(0, points.length - 1);
        offset += Math.max(1, points.length) + gap;
        return { label, color, points, start, end };
      });
    }

    function drawTraffic() {
      const svg = document.getElementById("trafficChart");
      const width = 940, height = 330;
      const pad = { left: 64, right: 24, top: 24, bottom: 50 };
      const chartW = width - pad.left - pad.right;
      const chartH = height - pad.top - pad.bottom;
      const series = combinedSeries();
      const all = series.flatMap(s => s.points);
      const maxX = Math.max(1, ...all.map(p => p.x));
      const maxY = Math.max(1, ...all.map(p => p.y)) * 1.08;
      const xScale = x => pad.left + (x / maxX) * chartW;
      const yScale = y => pad.top + chartH - (y / maxY) * chartH;
      const grid = [];
      for (let i = 0; i <= 4; i++) {
        const y = pad.top + chartH * i / 4;
        const value = maxY * (1 - i / 4);
        grid.push(`<line x1="${pad.left}" y1="${y}" x2="${width - pad.right}" y2="${y}" stroke="#e8ecf2"/>`);
        grid.push(`<text x="${pad.left - 10}" y="${y + 4}" text-anchor="end" font-size="12" fill="#667085">${fmt(value, 1)}</text>`);
      }
      const lines = series.map(s => {
        if (!s.points.length) return "";
        const path = s.points.map((point, idx) => `${idx === 0 ? "M" : "L"} ${xScale(point.x).toFixed(1)} ${yScale(point.y).toFixed(1)}`).join(" ");
        const labelX = xScale((s.start + s.end) / 2);
        return `
          <path d="${path}" fill="none" stroke="${s.color}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
          <text x="${labelX}" y="${height - 17}" text-anchor="middle" font-size="13" font-weight="700" fill="${s.color}">${s.label}</text>
        `;
      }).join("");
      svg.innerHTML = `
        <rect x="0" y="0" width="${width}" height="${height}" fill="#fff"/>
        <text x="${pad.left}" y="16" font-size="13" fill="#667085">Packets per second</text>
        ${grid.join("")}
        <line x1="${pad.left}" y1="${pad.top + chartH}" x2="${width - pad.right}" y2="${pad.top + chartH}" stroke="#b9c1cf"/>
        <line x1="${pad.left}" y1="${pad.top}" x2="${pad.left}" y2="${pad.top + chartH}" stroke="#b9c1cf"/>
        ${lines}
      `;
    }

    function eventTimeMs(window, key) {
      const value = window[key];
      if (!value) return null;
      const parsed = new Date(value).getTime();
      return Number.isNaN(parsed) ? null : parsed;
    }

    function drawPipeline() {
      const svg = document.getElementById("pipelineChart");
      const windows = DATA.windows || [];
      const width = 520, height = 330;
      const pad = { left: 70, right: 22, top: 34, bottom: 50 };
      const rows = Math.max(1, windows.length);
      const rowGap = Math.min(48, (height - pad.top - pad.bottom) / rows);
      const times = [];
      windows.forEach(window => {
        ["captureStartedAt", "captureEndedAt", "decisionGeneratedAt", "firstActionAt", "lastActionAt"].forEach(key => {
          const time = eventTimeMs(window, key);
          if (time !== null) times.push(time);
        });
      });
      if (!times.length) {
        svg.innerHTML = `<text x="24" y="40" font-size="13" fill="#667085">未找到实时窗口时间记录</text>`;
        return;
      }
      const minT = Math.min(...times);
      const maxT = Math.max(...times, minT + 1000);
      const span = Math.max(1000, maxT - minT);
      const xScale = time => pad.left + ((time - minT) / span) * (width - pad.left - pad.right);
      const lanes = windows.map((window, idx) => {
        const y = pad.top + idx * rowGap + rowGap * 0.45;
        const captureStart = eventTimeMs(window, "captureStartedAt");
        const captureEnd = eventTimeMs(window, "captureEndedAt");
        const decision = eventTimeMs(window, "decisionGeneratedAt");
        const firstAction = eventTimeMs(window, "firstActionAt");
        const lastAction = eventTimeMs(window, "lastActionAt");
        const captureRect = captureStart !== null && captureEnd !== null
          ? `<rect x="${xScale(captureStart)}" y="${y - 8}" width="${Math.max(4, xScale(captureEnd) - xScale(captureStart))}" height="16" rx="4" fill="#1d5fd1"/>`
          : "";
        const waitLine = captureEnd !== null && decision !== null
          ? `<line x1="${xScale(captureEnd)}" y1="${y}" x2="${xScale(decision)}" y2="${y}" stroke="#b9c1cf" stroke-width="2" stroke-dasharray="5 5"/>`
          : "";
        const decisionDot = decision !== null
          ? `<circle cx="${xScale(decision)}" cy="${y}" r="6" fill="#b54708"/>`
          : "";
        const blockLine = firstAction !== null && lastAction !== null
          ? `<rect x="${xScale(firstAction)}" y="${y - 8}" width="${Math.max(4, xScale(lastAction) - xScale(firstAction))}" height="16" rx="4" fill="#0e9384"/>`
          : "";
        const firstDot = firstAction !== null
          ? `<circle cx="${xScale(firstAction)}" cy="${y}" r="5" fill="#039855"/>`
          : "";
        const label = `窗口 ${Number(window.index)}`;
        const summary = `${fmt(window.decisions)} 决策 / ${fmt(window.actionCount)} 封禁`;
        return `
          <text x="12" y="${y + 4}" font-size="12" fill="#172033" font-weight="700">${label}</text>
          <line x1="${pad.left}" y1="${y}" x2="${width - pad.right}" y2="${y}" stroke="#edf0f5"/>
          ${captureRect}${waitLine}${decisionDot}${blockLine}${firstDot}
          <text x="${width - pad.right}" y="${y + 4}" text-anchor="end" font-size="11" fill="#667085">${summary}</text>
        `;
      }).join("");
      const legendY = height - 20;
      svg.innerHTML = `
        <rect x="0" y="0" width="${width}" height="${height}" fill="#fff"/>
        <text x="${pad.left}" y="18" font-size="13" fill="#667085">抓包、推理完成、封禁动作的真实时间顺序</text>
        ${lanes}
        <rect x="${pad.left}" y="${legendY - 10}" width="18" height="10" rx="3" fill="#1d5fd1"/>
        <text x="${pad.left + 24}" y="${legendY}" font-size="11" fill="#667085">抓包</text>
        <circle cx="${pad.left + 94}" cy="${legendY - 5}" r="5" fill="#b54708"/>
        <text x="${pad.left + 106}" y="${legendY}" font-size="11" fill="#667085">推理完成</text>
        <rect x="${pad.left + 190}" y="${legendY - 10}" width="18" height="10" rx="3" fill="#0e9384"/>
        <text x="${pad.left + 214}" y="${legendY}" font-size="11" fill="#667085">封禁</text>
        <text x="${width - pad.right}" y="${legendY}" text-anchor="end" font-size="11" fill="#667085">${clock(new Date(minT).toISOString())} - ${clock(new Date(maxT).toISOString())}</text>
      `;
    }

    function drawDecision() {
      const svg = document.getElementById("decisionChart");
      const data = DATA.decision.histogram || [];
      const width = 600, height = 290;
      const pad = { left: 42, right: 18, top: 20, bottom: 58 };
      const chartW = width - pad.left - pad.right;
      const chartH = height - pad.top - pad.bottom;
      const maxY = Math.max(1, ...data.map(d => d.count));
      const barGap = 7;
      const barW = chartW / Math.max(1, data.length) - barGap;
      const bars = data.map((d, i) => {
        const h = (d.count / maxY) * chartH;
        const x = pad.left + i * (barW + barGap);
        const y = pad.top + chartH - h;
        return `
          <rect x="${x}" y="${y}" width="${barW}" height="${h}" rx="3" fill="${d.count ? "#1d5fd1" : "#d7dce4"}"/>
          <text x="${x + barW / 2}" y="${height - 33}" text-anchor="middle" font-size="10" fill="#667085" transform="rotate(-25 ${x + barW / 2} ${height - 33})">${d.label}</text>
          ${d.count ? `<text x="${x + barW / 2}" y="${Math.max(14, y - 5)}" text-anchor="middle" font-size="11" fill="#172033">${d.count}</text>` : ""}
        `;
      }).join("");
      svg.innerHTML = `
        <rect x="0" y="0" width="${width}" height="${height}" fill="#fff"/>
        <text x="${pad.left}" y="16" font-size="13" fill="#667085">Confidence distribution</text>
        <line x1="${pad.left}" y1="${pad.top + chartH}" x2="${width - pad.right}" y2="${pad.top + chartH}" stroke="#b9c1cf"/>
        <line x1="${pad.left}" y1="${pad.top}" x2="${pad.left}" y2="${pad.top + chartH}" stroke="#b9c1cf"/>
        ${bars}
      `;
    }

    function renderWindowTable() {
      const rows = (DATA.windows || []).map(window => `
        <tr>
          <td><strong>${Number(window.index)}</strong></td>
          <td>${clock(window.captureStartedAt)}</td>
          <td>${sec(window.captureSeconds)}</td>
          <td>${clock(window.decisionGeneratedAt)}</td>
          <td>${window.firstActionAt ? clock(window.firstActionAt) : "-"}</td>
          <td>${window.firstActionAt ? sec(window.firstActionLatencySec) : "-"}</td>
          <td>${fmt(window.maxPps)}</td>
          <td>${fmt(window.decisions)}</td>
          <td>${fmt(window.actionCount)}</td>
          <td>${Number(window.maxConfidence || 0).toFixed(3)}</td>
          <td class="${statusClass(window.applyStatus)}">${window.applyStatus || "-"}</td>
        </tr>
      `).join("");
      setHTML("windowTable", `
        <table>
          <thead>
            <tr>
              <th>窗口</th><th>抓包开始</th><th>抓包</th><th>推理完成</th><th>首封</th>
              <th>首封延迟</th><th>峰值 PPS</th><th>决策</th><th>封禁</th><th>最高置信度</th><th>状态</th>
            </tr>
          </thead>
          <tbody>${rows || `<tr><td colspan="11">未找到实时窗口记录</td></tr>`}</tbody>
        </table>
      `);
    }

    function renderActions() {
      const actions = DATA.actions || [];
      if (!actions.length) {
        setHTML("actionsList", `<div class="mini-row"><span>封禁日志</span><strong>未记录</strong></div>`);
        return;
      }
      setHTML("actionsList", actions.slice(0, 12).map(action => `
        <div class="mini-row">
          <span>${action.timestamp} · ${action.ip || "-"} · ${action.reason || "-"}</span>
          <strong>${action.action || "-"}</strong>
        </div>
      `).join(""));
    }

    function renderPaths() {
      setHTML("filePaths", `
        Features: ${DATA.directories.features}<br>
        Logs: ${DATA.directories.logs}<br>
        PCAP: ${DATA.directories.pcap}<br>
        Decision: ${DATA.decision.path || "-"}<br>
        Normal CSV: ${DATA.normal.summary.path || "-"}<br>
        Realtime attack CSV: ${DATA.attack.summary.path || "-"}
      `);
    }

    kpis();
    drawTraffic();
    drawPipeline();
    drawDecision();
    renderWindowTable();
    renderActions();
    renderPaths();
  </script>
</body>
</html>
"""
    return (
        template.replace("__DATA__", json_data)
        .replace("__TITLE__", title)
        .replace("__RUN_ID__", run_id)
    )


def main() -> None:
    args = parse_args()
    root = Path.cwd()
    run_id = args.run_id or latest_realtime_run(root)
    output = (
        Path(args.output)
        if args.output
        else root / "data" / "logs" / run_id / f"realtime_visualization_{run_id}.html"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    data = collect_data(root, run_id, args.title)
    output.write_text(render_html(data), encoding="utf-8")
    print(f"Generated realtime visualization: {output}")


if __name__ == "__main__":
    main()
