from collections import defaultdict
import json

import pandas as pd

from storage.redis_store import RedisStore, persist_defense_actions


class FakeRedis:
    def __init__(self):
        self.sets = defaultdict(set)
        self.hashes = defaultdict(dict)
        self.streams = defaultdict(list)

    def sadd(self, key, value):
        self.sets[key].add(value)

    def hset(self, key, mapping):
        self.hashes[key].update(mapping)

    def delete(self, key):
        self.streams.pop(key, None)

    def xadd(self, key, fields):
        self.streams[key].append(fields)
        return f"{len(self.streams[key])}-0"


def test_redis_store_writes_feature_stream_and_metadata():
    client = FakeRedis()
    store = RedisStore(client, prefix="test")
    frame = pd.DataFrame(
        [
            {
                "timestamp": "2026-06-05T12:00:00+08:00",
                "src_ip": "10.0.0.9",
                "dst_ip": "10.0.0.2",
                "protocol": "TCP",
                "pps": 120.0,
                "label": "attack",
                "attack_type": "mixed_attack",
            }
        ]
    )

    info = store.save_feature_frame(
        frame,
        output_path="data/features/demo_run/attack_before_defense_demo_run.csv",
        input_path="data/pcap/demo_run/attack_before_defense_demo_run.pcap",
        label="attack",
        attack_type="mixed_attack",
        target_ip="10.0.0.2",
        window_size=1.0,
    )

    stream_key = "test:run:demo_run:features:attack_before_defense_demo_run"
    artifact_key = "test:run:demo_run:artifact:attack_before_defense_demo_run"
    assert info["key"] == stream_key
    assert client.sets["test:runs"] == {"demo_run"}
    assert client.hashes[artifact_key]["row_count"] == "1"
    assert client.streams[stream_key][0]["src_ip"] == "10.0.0.9"
    assert client.streams[stream_key][0]["pps"] == "120.0"


def test_redis_store_writes_decisions_and_defense_actions():
    client = FakeRedis()
    store = RedisStore(client, prefix="test")
    report = {
        "generated_at": "2026-06-05T12:00:01+08:00",
        "threshold": 0.8,
        "decisions": [
            {
                "src_ip": "10.0.0.9",
                "label": "attack",
                "attack_type": "mixed_attack",
                "confidence": 0.96,
                "action": "block",
                "reason": "model_detected_mixed_attack",
            }
        ],
    }

    decision_info = store.save_decision_report(
        report,
        output_path="data/logs/demo_run/decision_demo_run.json",
        input_path="data/features/demo_run/attack_before_defense_demo_run.csv",
        model_path="models/saved/model.pth",
    )
    action_info = store.save_defense_actions(
        [
            {
                "src_ip": "10.0.0.9",
                "reason": "model_detected_mixed_attack",
                "confidence": 0.96,
                "returncode": 0,
                "status": "applied",
            }
        ],
        decision_path="data/logs/demo_run/decision_demo_run.json",
    )

    decision_stream = "test:run:demo_run:decision:decision_demo_run:items"
    action_stream = "test:run:demo_run:defense_actions"
    assert decision_info["rows"] == 1
    assert action_info["rows"] == 1
    assert client.hashes["test:run:demo_run:decision:decision_demo_run"]["decision_count"] == "1"
    assert client.streams[decision_stream][0]["confidence"] == "0.96"
    assert client.streams[action_stream][0]["status"] == "applied"


def test_redis_store_writes_demo_summary():
    client = FakeRedis()
    store = RedisStore(client, prefix="test")

    info = store.save_demo_summary(
        {
            "run_id": "demo_run",
            "status": "completed",
            "completed_at": "2026-06-07T12:00:00+00:00",
            "target_ip": "127.0.0.1",
            "target_port": "8080",
            "target_url": "http://127.0.0.1:8080/",
            "decision_count": 2,
            "paths": {
                "decision_json": "data/logs/demo_run/decision_demo_run.json",
                "feature_dir": "data/features/demo_run",
            },
        },
        run_id="demo_run",
    )

    summary_key = "test:run:demo_run:summary"
    assert info["key"] == summary_key
    assert client.sets["test:run:demo_run:artifacts"] == {"demo_summary"}
    assert client.hashes["test:run:demo_run"]["status"] == "completed"
    assert client.hashes["test:run:demo_run"]["summary_key"] == summary_key
    assert client.hashes[summary_key]["decision_count"] == "2"
    assert json.loads(client.hashes[summary_key]["paths"])["feature_dir"] == "data/features/demo_run"


def test_redis_store_appends_live_features_and_events():
    client = FakeRedis()
    store = RedisStore(client, prefix="test")

    feature_info = store.append_live_feature_rows(
        [
            {
                "timestamp": "2026-06-07T12:00:00+00:00",
                "src_ip": "10.0.0.9",
                "dst_ip": "10.0.0.2",
                "protocol": "TCP",
                "pps": 200.0,
                "syn_count": 50,
            }
        ],
        run_id="demo_run",
        phase="attack_before_defense",
    )
    event_info = store.append_live_event(
        {"event": "phase_started", "phase": "attack_before_defense"},
        run_id="demo_run",
    )

    live_key = "test:run:demo_run:live_features"
    event_key = "test:run:demo_run:events"
    assert feature_info["key"] == live_key
    assert event_info["key"] == event_key
    assert client.hashes["test:run:demo_run"]["last_live_phase"] == "attack_before_defense"
    assert client.streams[live_key][0]["phase"] == "attack_before_defense"
    assert client.streams[live_key][0]["pps"] == "200.0"
    assert client.streams[event_key][0]["event"] == "phase_started"


def test_persist_helper_noops_when_storage_is_disabled(monkeypatch):
    monkeypatch.delenv("STORAGE_BACKEND", raising=False)

    assert persist_defense_actions([]) is None
