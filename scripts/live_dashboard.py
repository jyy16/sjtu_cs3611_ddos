#!/usr/bin/env python3
"""Serve a small live dashboard backed by Redis streams."""

from __future__ import annotations

import argparse
import json
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from storage.redis_store import DEFAULT_PREFIX, DEFAULT_REDIS_URL


def redis_client(redis_url: str) -> Any:
    import redis

    client = redis.Redis.from_url(redis_url, decode_responses=True)
    client.ping()
    return client


def key(prefix: str, *parts: str) -> str:
    return ":".join([prefix.strip(":") or DEFAULT_PREFIX, *[str(part).strip(":") for part in parts]])


def stream_tail(client: Any, stream_key: str, count: int) -> list[dict[str, Any]]:
    entries = client.xrevrange(stream_key, "+", "-", count=count)
    entries.reverse()
    return [{"id": entry_id, **fields} for entry_id, fields in entries]


def snapshot(client: Any, prefix: str, run_id: str, count: int) -> dict[str, Any]:
    run_key = key(prefix, "run", run_id)
    meta = client.hgetall(run_key)
    live_key = key(prefix, "run", run_id, "live_features")
    event_key = key(prefix, "run", run_id, "events")
    action_key = key(prefix, "run", run_id, "defense_actions")

    last_decision = meta.get("last_decision", "")
    decision = {}
    decision_items: list[dict[str, Any]] = []
    if last_decision:
        decision = client.hgetall(key(prefix, "run", run_id, "decision", last_decision))
        decision_items = stream_tail(client, key(prefix, "run", run_id, "decision", last_decision, "items"), 50)

    return {
        "runId": run_id,
        "meta": meta,
        "liveFeatures": stream_tail(client, live_key, count),
        "events": stream_tail(client, event_key, 80),
        "defenseActions": stream_tail(client, action_key, 80),
        "decision": decision,
        "decisionItems": decision_items,
    }


def dashboard_html(run_id: str) -> str:
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Live DDoS Demo - {run_id}</title>
  <style>
    :root {{
      --bg: #f7f8fa;
      --surface: #ffffff;
      --ink: #172033;
      --muted: #667085;
      --line: #d9dee7;
      --blue: #1d5fd1;
      --red: #d92d20;
      --green: #039855;
      --teal: #0e9384;
      --amber: #b54708;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: Inter, "Segoe UI", "Microsoft YaHei", Arial, sans-serif;
      letter-spacing: 0;
    }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      padding: 18px 24px;
      background: var(--surface);
      border-bottom: 1px solid var(--line);
      position: sticky;
      top: 0;
      z-index: 2;
    }}
    h1 {{ margin: 0; font-size: 22px; line-height: 1.15; }}
    main {{ max-width: 1280px; margin: 0 auto; padding: 20px 24px 30px; }}
    .muted {{ color: var(--muted); font-size: 13px; }}
    .status {{ display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--muted); }}
    .dot {{ width: 10px; height: 10px; border-radius: 50%; background: var(--amber); }}
    .dot.ok {{ background: var(--green); }}
    .grid {{ display: grid; gap: 14px; }}
    .kpis {{ grid-template-columns: repeat(5, minmax(0, 1fr)); }}
    .two {{ grid-template-columns: minmax(0, 1.45fr) minmax(360px, 0.55fr); }}
    .card {{
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      min-width: 0;
    }}
    .label {{ color: var(--muted); font-size: 12px; margin-bottom: 7px; }}
    .value {{ font-size: 28px; font-weight: 800; line-height: 1; white-space: nowrap; }}
    .sub {{ margin-top: 8px; color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }}
    .red {{ color: var(--red); }} .green {{ color: var(--green); }} .blue {{ color: var(--blue); }} .teal {{ color: var(--teal); }}
    section {{ margin-bottom: 14px; }}
    h2 {{ margin: 0 0 12px; font-size: 16px; }}
    svg {{ display: block; width: 100%; height: auto; }}
    .list {{ display: grid; gap: 8px; max-height: 420px; overflow: auto; }}
    .row {{ display: grid; grid-template-columns: 118px minmax(0, 1fr); gap: 10px; padding-bottom: 8px; border-bottom: 1px solid #edf0f5; font-size: 13px; }}
    .row strong {{ overflow-wrap: anywhere; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ padding: 9px 8px; border-bottom: 1px solid #edf0f5; text-align: right; white-space: nowrap; }}
    th:first-child, td:first-child {{ text-align: left; }}
    th {{ color: var(--muted); font-size: 12px; }}
    @media (max-width: 980px) {{
      .kpis, .two {{ grid-template-columns: 1fr; }}
      header {{ align-items: flex-start; flex-direction: column; }}
      main {{ padding: 16px; }}
      .value {{ font-size: 24px; }}
      th, td {{ white-space: normal; }}
    }}
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Live DDoS Demo</h1>
      <div class="muted">Run ID: <strong id="runId">{run_id}</strong></div>
    </div>
    <div class="status"><span class="dot" id="dot"></span><span id="status">connecting</span></div>
  </header>
  <main>
    <section class="grid kpis" id="kpis"></section>
    <section class="grid two">
      <div class="card">
        <h2>实时特征曲线</h2>
        <svg id="chart" viewBox="0 0 940 360" role="img" aria-label="live traffic chart"></svg>
      </div>
      <div class="card">
        <h2>实时事件</h2>
        <div class="list" id="events"></div>
      </div>
    </section>
    <section class="grid two">
      <div class="card">
        <h2>最新窗口</h2>
        <div id="latestTable"></div>
      </div>
      <div class="card">
        <h2>模型与防御</h2>
        <div class="list" id="decision"></div>
      </div>
    </section>
  </main>
  <script>
    const RUN_ID = {json.dumps(run_id)};
    const COLORS = {{
      normal: "#039855",
      attack_before_defense: "#d92d20",
      attack_after_defense: "#0e9384",
      defense: "#b54708",
      unknown: "#1d5fd1"
    }};

    function num(value) {{
      const n = Number(value);
      return Number.isFinite(n) ? n : 0;
    }}

    function fmt(value, digits = 0) {{
      const n = num(value);
      if (Math.abs(n) >= 1000000) return (n / 1000000).toFixed(2) + "M";
      if (Math.abs(n) >= 1000) return (n / 1000).toFixed(1) + "K";
      return n.toLocaleString(undefined, {{ maximumFractionDigits: digits }});
    }}

    function aggregate(rows) {{
      const buckets = new Map();
      for (const row of rows) {{
        const key = `${{row.timestamp || ""}}|${{row.phase || "unknown"}}`;
        if (!buckets.has(key)) {{
          buckets.set(key, {{
            timestamp: row.timestamp || "",
            phase: row.phase || "unknown",
            pps: 0,
            bps: 0,
            syn: 0,
            unique: 0,
            rows: 0
          }});
        }}
        const bucket = buckets.get(key);
        bucket.pps += num(row.pps);
        bucket.bps += num(row.bps);
        bucket.syn += num(row.syn_count);
        bucket.unique = Math.max(bucket.unique, num(row.unique_src_ips));
        bucket.rows += 1;
      }}
      return Array.from(buckets.values()).sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    }}

    function drawChart(points) {{
      const svg = document.getElementById("chart");
      const width = 940, height = 360;
      const pad = {{ left: 68, right: 24, top: 24, bottom: 56 }};
      const chartW = width - pad.left - pad.right;
      const chartH = height - pad.top - pad.bottom;
      const maxY = Math.max(1, ...points.map(p => p.pps));
      const xScale = i => pad.left + (points.length <= 1 ? 0 : i / (points.length - 1) * chartW);
      const yScale = y => pad.top + chartH - y / (maxY * 1.1) * chartH;
      const grid = [];
      for (let i = 0; i <= 4; i++) {{
        const y = pad.top + chartH * i / 4;
        const v = maxY * 1.1 * (1 - i / 4);
        grid.push(`<line x1="${{pad.left}}" y1="${{y}}" x2="${{width - pad.right}}" y2="${{y}}" stroke="#e8ecf2"/>`);
        grid.push(`<text x="${{pad.left - 10}}" y="${{y + 4}}" text-anchor="end" font-size="12" fill="#667085">${{fmt(v)}}</text>`);
      }}
      const segments = [];
      for (let i = 1; i < points.length; i++) {{
        const a = points[i - 1];
        const b = points[i];
        const color = COLORS[b.phase] || COLORS.unknown;
        segments.push(`<line x1="${{xScale(i - 1)}}" y1="${{yScale(a.pps)}}" x2="${{xScale(i)}}" y2="${{yScale(b.pps)}}" stroke="${{color}}" stroke-width="3" stroke-linecap="round"/>`);
      }}
      const dots = points.map((p, i) => `<circle cx="${{xScale(i)}}" cy="${{yScale(p.pps)}}" r="3" fill="${{COLORS[p.phase] || COLORS.unknown}}"/>`).join("");
      svg.innerHTML = `
        <rect x="0" y="0" width="${{width}}" height="${{height}}" fill="#fff"/>
        <text x="${{pad.left}}" y="16" font-size="13" fill="#667085">PPS by 1-second feature windows</text>
        ${{grid.join("")}}
        <line x1="${{pad.left}}" y1="${{pad.top + chartH}}" x2="${{width - pad.right}}" y2="${{pad.top + chartH}}" stroke="#b9c1cf"/>
        <line x1="${{pad.left}}" y1="${{pad.top}}" x2="${{pad.left}}" y2="${{pad.top + chartH}}" stroke="#b9c1cf"/>
        ${{segments.join("")}}
        ${{dots}}
        <text x="${{pad.left}}" y="${{height - 20}}" font-size="12" fill="#667085">green normal, red attack before defense, teal attack after defense</text>
      `;
    }}

    function renderKpis(data, points) {{
      const latest = points[points.length - 1] || {{}};
      const event = (data.events || [])[data.events.length - 1] || {{}};
      document.getElementById("kpis").innerHTML = `
        <div class="card"><div class="label">当前阶段</div><div class="value blue">${{latest.phase || event.phase || "-"}}</div><div class="sub">${{event.event || "waiting"}}</div></div>
        <div class="card"><div class="label">实时 PPS</div><div class="value red">${{fmt(latest.pps)}}</div><div class="sub">latest feature window</div></div>
        <div class="card"><div class="label">实时 Mbps</div><div class="value blue">${{fmt((latest.bps || 0) / 1000000, 3)}}</div><div class="sub">bits per second</div></div>
        <div class="card"><div class="label">SYN 数</div><div class="value teal">${{fmt(latest.syn)}}</div><div class="sub">current window</div></div>
        <div class="card"><div class="label">特征行</div><div class="value green">${{fmt((data.liveFeatures || []).length)}}</div><div class="sub">Redis live stream tail</div></div>
      `;
    }}

    function renderEvents(events) {{
      document.getElementById("events").innerHTML = (events || []).slice(-18).reverse().map(e => `
        <div class="row"><span>${{(e.timestamp || "").slice(11, 19)}}</span><strong>${{e.event || "-"}} ${{e.phase ? " / " + e.phase : ""}}</strong></div>
      `).join("") || `<div class="muted">No events yet.</div>`;
    }}

    function renderLatest(rows) {{
      const latestRows = (rows || []).slice(-10).reverse();
      document.getElementById("latestTable").innerHTML = `
        <table>
          <thead><tr><th>phase</th><th>src</th><th>proto</th><th>PPS</th><th>SYN</th><th>unique</th></tr></thead>
          <tbody>${{latestRows.map(r => `
            <tr><td>${{r.phase || ""}}</td><td>${{r.src_ip || ""}}</td><td>${{r.protocol || ""}}</td><td>${{fmt(r.pps)}}</td><td>${{fmt(r.syn_count)}}</td><td>${{fmt(r.unique_src_ips)}}</td></tr>
          `).join("")}}</tbody>
        </table>
      `;
    }}

    function renderDecision(data) {{
      const decisions = data.decisionItems || [];
      const actions = data.defenseActions || [];
      const decisionRows = decisions.slice(-8).reverse().map(d => `
        <div class="row"><span>${{d.src_ip || "-"}}</span><strong>${{d.action || "-"}} / ${{d.confidence || "-"}}</strong></div>
      `).join("");
      const actionRows = actions.slice(-8).reverse().map(a => `
        <div class="row"><span>${{a.src_ip || "-"}}</span><strong>${{a.status || "-"}} / ${{a.reason || "-"}}</strong></div>
      `).join("");
      document.getElementById("decision").innerHTML = decisionRows + actionRows || `<div class="muted">Waiting for model decisions.</div>`;
    }}

    async function tick() {{
      try {{
        const response = await fetch(`/api/snapshot?run_id=${{encodeURIComponent(RUN_ID)}}&count=500`, {{ cache: "no-store" }});
        if (!response.ok) throw new Error(await response.text());
        const data = await response.json();
        const points = aggregate(data.liveFeatures || []);
        document.getElementById("dot").className = "dot ok";
        document.getElementById("status").textContent = `live / ${{new Date().toLocaleTimeString()}}`;
        renderKpis(data, points);
        drawChart(points);
        renderEvents(data.events);
        renderLatest(data.liveFeatures);
        renderDecision(data);
      }} catch (error) {{
        document.getElementById("dot").className = "dot";
        document.getElementById("status").textContent = String(error).slice(0, 160);
      }}
    }}

    tick();
    setInterval(tick, 1000);
  </script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "LiveDDoSDashboard/1.0"

    def send_text(self, status: HTTPStatus, body: str, content_type: str = "text/plain; charset=utf-8") -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.send_text(HTTPStatus.OK, dashboard_html(self.server.run_id), "text/html; charset=utf-8")
            return
        if parsed.path == "/api/snapshot":
            query = parse_qs(parsed.query)
            run_id = query.get("run_id", [self.server.run_id])[0]
            count = int(query.get("count", ["500"])[0])
            try:
                payload = snapshot(self.server.redis, self.server.prefix, run_id, count)
            except Exception as exc:
                self.send_text(HTTPStatus.SERVICE_UNAVAILABLE, json.dumps({"error": str(exc)}))
                return
            self.send_text(HTTPStatus.OK, json.dumps(payload, ensure_ascii=False), "application/json; charset=utf-8")
            return
        self.send_text(HTTPStatus.NOT_FOUND, "not found")

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("[live-dashboard] " + fmt % args + "\n")


class DashboardServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler], args: argparse.Namespace) -> None:
        super().__init__(address, handler)
        self.run_id = args.run_id
        self.prefix = args.prefix
        self.redis = redis_client(args.redis_url)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Serve a live Redis dashboard for one demo run.")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--redis-url", default=DEFAULT_REDIS_URL)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        server = DashboardServer((args.host, args.port), Handler, args)
    except Exception as exc:
        print(f"[live-dashboard][error] {exc}", file=sys.stderr, flush=True)
        return 1
    print(f"Live dashboard: http://{args.host}:{args.port}/?run_id={args.run_id}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
