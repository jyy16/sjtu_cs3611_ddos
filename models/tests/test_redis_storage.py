from collections import defaultdict

import pandas as pd

from storage.redis_store import RedisStore, persist_defense_actions, persist_defense_block_log


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


def test_redis_store_writes_defense_block_log_stream():
    client = FakeRedis()
    store = RedisStore(client, prefix="test")

    info = store.save_defense_block_log(
        [
            {
                "timestamp": "2026-06-08T10:55:32+08:00",
                "action": "rate_limit_loopback",
                "src_ip": "127.0.0.1",
                "reason": "model_detected_mixed_attack",
                "ttl": 300,
                "project_tag": "cs3611-ddos",
            }
        ],
        log_path="data/logs/demo_run/defense_blocks.log",
        artifact="defense_blocks_demo_run",
    )

    stream_key = "test:run:demo_run:defense_block_log"
    summary_key = "test:run:demo_run:defense_block_log_summary:defense_blocks_demo_run"
    assert info["key"] == stream_key
    assert info["rows"] == 1
    assert client.hashes[summary_key]["row_count"] == "1"
    assert client.streams[stream_key][0]["src_ip"] == "127.0.0.1"
    assert client.streams[stream_key][0]["action"] == "rate_limit_loopback"


def test_persist_helper_noops_when_storage_is_disabled(monkeypatch):
    monkeypatch.delenv("STORAGE_BACKEND", raising=False)

    assert persist_defense_actions([]) is None
    assert persist_defense_block_log([]) is None
