"""Redis persistence helpers for demo features, decisions, and defense actions."""

from __future__ import annotations

import json
import math
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping


DEFAULT_PREFIX = "cs3611:ddos"
DEFAULT_REDIS_URL = "redis://127.0.0.1:6379/0"
DISABLED_BACKENDS = {"", "none", "off", "false", "0", "file", "files", "disabled"}


class StorageError(RuntimeError):
    """Raised when an enabled storage backend cannot persist an artifact."""


def storage_backend() -> str:
    return os.getenv("STORAGE_BACKEND", "none").strip().lower()


def storage_enabled() -> bool:
    return storage_backend() not in DISABLED_BACKENDS


def storage_fail_open() -> bool:
    return os.getenv("STORAGE_FAIL_OPEN", "0").strip().lower() in {"1", "true", "yes", "on"}


def _warn(message: str) -> None:
    print(f"[storage][warn] {message}", file=sys.stderr, flush=True)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _jsonable(value: Any) -> Any:
    if hasattr(value, "item"):
        try:
            value = value.item()
        except (TypeError, ValueError):
            pass
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except (TypeError, ValueError):
            return str(value)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _field_value(value: Any) -> str:
    value = _jsonable(value)
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _mapping(values: Mapping[str, Any]) -> dict[str, str]:
    return {str(key): _field_value(value) for key, value in values.items()}


def _records_from_frame(frame: Any) -> list[dict[str, Any]]:
    if hasattr(frame, "to_dict"):
        records = frame.to_dict(orient="records")
        return [dict(record) for record in records]
    return [dict(record) for record in frame]


def resolve_run_id(path: str | Path | None = None, explicit: str | None = None) -> str:
    if explicit:
        return explicit
    env_run_id = os.getenv("RUN_ID")
    if env_run_id:
        return env_run_id
    if path is not None:
        parts = Path(path).parts
        for anchor in ("features", "logs", "pcap"):
            if anchor in parts:
                index = parts.index(anchor)
                if index + 1 < len(parts):
                    return parts[index + 1]
    return "adhoc"


def artifact_name(path: str | Path | None = None, explicit: str | None = None) -> str:
    if explicit:
        return explicit
    if path is None:
        return "artifact"
    return Path(path).stem


class RedisStore:
    def __init__(self, client: Any, prefix: str = DEFAULT_PREFIX) -> None:
        self.client = client
        self.prefix = prefix.strip(":") or DEFAULT_PREFIX

    def key(self, *parts: str) -> str:
        return ":".join([self.prefix, *[str(part).strip(":") for part in parts]])

    def _touch_run(self, run_id: str, fields: Mapping[str, Any] | None = None) -> None:
        now = _now()
        mapping = {"run_id": run_id, "updated_at": now}
        if fields:
            mapping.update(fields)
        self.client.sadd(self.key("runs"), run_id)
        self.client.hset(self.key("run", run_id), mapping=_mapping(mapping))

    def save_feature_frame(
        self,
        frame: Any,
        *,
        output_path: str | Path,
        input_path: str | Path | None = None,
        label: str | None = None,
        attack_type: str | None = None,
        target_ip: str | None = None,
        window_size: float | None = None,
        run_id: str | None = None,
        artifact: str | None = None,
    ) -> dict[str, Any]:
        resolved_run_id = resolve_run_id(output_path, explicit=run_id)
        resolved_artifact = artifact_name(output_path, explicit=artifact)
        records = _records_from_frame(frame)
        stream_key = self.key("run", resolved_run_id, "features", resolved_artifact)
        artifact_key = self.key("run", resolved_run_id, "artifact", resolved_artifact)

        self._touch_run(resolved_run_id, {"last_artifact": resolved_artifact})
        self.client.sadd(self.key("run", resolved_run_id, "artifacts"), resolved_artifact)
        self.client.delete(stream_key)
        self.client.hset(
            artifact_key,
            mapping=_mapping(
                {
                    "type": "features",
                    "artifact": resolved_artifact,
                    "output_path": str(output_path),
                    "input_path": str(input_path or ""),
                    "label": label or "",
                    "attack_type": attack_type or "",
                    "target_ip": target_ip or "",
                    "window_size": "" if window_size is None else window_size,
                    "row_count": len(records),
                    "stream_key": stream_key,
                    "stored_at": _now(),
                }
            ),
        )

        for index, record in enumerate(records):
            fields = {"row_index": index, **record}
            self.client.xadd(stream_key, _mapping(fields))

        return {
            "backend": "redis",
            "run_id": resolved_run_id,
            "artifact": resolved_artifact,
            "key": stream_key,
            "rows": len(records),
        }

    def save_decision_report(
        self,
        report: Mapping[str, Any],
        *,
        output_path: str | Path,
        input_path: str | Path | None = None,
        model_path: str | Path | None = None,
        run_id: str | None = None,
        artifact: str | None = None,
    ) -> dict[str, Any]:
        resolved_run_id = resolve_run_id(output_path, explicit=run_id)
        resolved_artifact = artifact_name(output_path, explicit=artifact)
        decisions = list(report.get("decisions", []))
        report_key = self.key("run", resolved_run_id, "decision", resolved_artifact)
        stream_key = self.key("run", resolved_run_id, "decision", resolved_artifact, "items")

        self._touch_run(resolved_run_id, {"last_decision": resolved_artifact})
        self.client.sadd(self.key("run", resolved_run_id, "artifacts"), resolved_artifact)
        self.client.delete(stream_key)
        self.client.hset(
            report_key,
            mapping=_mapping(
                {
                    "type": "decision",
                    "artifact": resolved_artifact,
                    "output_path": str(output_path),
                    "input_path": str(input_path or ""),
                    "model_path": str(model_path or ""),
                    "generated_at": report.get("generated_at", ""),
                    "threshold": report.get("threshold", ""),
                    "decision_count": len(decisions),
                    "stream_key": stream_key,
                    "raw_json": json.dumps(_jsonable(dict(report)), ensure_ascii=False, sort_keys=True),
                    "stored_at": _now(),
                }
            ),
        )

        for index, decision in enumerate(decisions):
            fields = {"decision_index": index, **dict(decision)}
            self.client.xadd(stream_key, _mapping(fields))

        return {
            "backend": "redis",
            "run_id": resolved_run_id,
            "artifact": resolved_artifact,
            "key": report_key,
            "rows": len(decisions),
        }

    def save_defense_actions(
        self,
        actions: Iterable[Mapping[str, Any]],
        *,
        decision_path: str | Path | None = None,
        run_id: str | None = None,
        artifact: str | None = None,
    ) -> dict[str, Any]:
        resolved_run_id = resolve_run_id(decision_path, explicit=run_id)
        resolved_artifact = artifact_name(decision_path, explicit=artifact)
        records = [dict(action) for action in actions]
        stream_key = self.key("run", resolved_run_id, "defense_actions")
        summary_key = self.key("run", resolved_run_id, "defense_summary", resolved_artifact)

        self._touch_run(resolved_run_id, {"last_defense_artifact": resolved_artifact})
        self.client.hset(
            summary_key,
            mapping=_mapping(
                {
                    "type": "defense_actions",
                    "artifact": resolved_artifact,
                    "decision_path": str(decision_path or ""),
                    "action_count": len(records),
                    "stream_key": stream_key,
                    "stored_at": _now(),
                }
            ),
        )

        for index, action in enumerate(records):
            fields = {"action_index": index, "artifact": resolved_artifact, **action}
            self.client.xadd(stream_key, _mapping(fields))

        return {
            "backend": "redis",
            "run_id": resolved_run_id,
            "artifact": resolved_artifact,
            "key": stream_key,
            "rows": len(records),
        }

    def save_demo_summary(
        self,
        summary: Mapping[str, Any],
        *,
        run_id: str | None = None,
        artifact: str | None = None,
    ) -> dict[str, Any]:
        resolved_run_id = resolve_run_id(explicit=run_id or str(summary.get("run_id") or ""))
        resolved_artifact = artifact or "demo_summary"
        summary_record = dict(summary)
        summary_record["run_id"] = resolved_run_id
        summary_key = self.key("run", resolved_run_id, "summary")

        self._touch_run(
            resolved_run_id,
            {
                "status": summary_record.get("status", "completed"),
                "completed_at": summary_record.get("completed_at", ""),
                "target_ip": summary_record.get("target_ip", ""),
                "target_port": summary_record.get("target_port", ""),
                "target_url": summary_record.get("target_url", ""),
                "decision_count": summary_record.get("decision_count", ""),
                "summary_key": summary_key,
            },
        )
        self.client.sadd(self.key("run", resolved_run_id, "artifacts"), resolved_artifact)
        self.client.hset(
            summary_key,
            mapping=_mapping(
                {
                    "type": "demo_summary",
                    "artifact": resolved_artifact,
                    **summary_record,
                    "raw_json": json.dumps(_jsonable(summary_record), ensure_ascii=False, sort_keys=True),
                    "stored_at": _now(),
                }
            ),
        )

        return {
            "backend": "redis",
            "run_id": resolved_run_id,
            "artifact": resolved_artifact,
            "key": summary_key,
            "rows": 1,
        }

    def append_live_feature_rows(
        self,
        rows: Iterable[Mapping[str, Any]],
        *,
        run_id: str,
        phase: str,
        artifact: str = "live_features",
    ) -> dict[str, Any]:
        records = [dict(row) for row in rows]
        stream_key = self.key("run", run_id, artifact)
        summary_key = self.key("run", run_id, "live_summary")

        self._touch_run(run_id, {"last_live_phase": phase, "live_stream_key": stream_key})
        self.client.sadd(self.key("run", run_id, "artifacts"), artifact)
        self.client.hset(
            summary_key,
            mapping=_mapping(
                {
                    "type": "live_features",
                    "artifact": artifact,
                    "stream_key": stream_key,
                    "last_phase": phase,
                    "last_row_count": len(records),
                    "updated_at": _now(),
                }
            ),
        )

        for index, row in enumerate(records):
            fields = {"row_index": index, "phase": phase, **row}
            self.client.xadd(stream_key, _mapping(fields))

        return {
            "backend": "redis",
            "run_id": run_id,
            "artifact": artifact,
            "key": stream_key,
            "rows": len(records),
        }

    def append_live_event(
        self,
        event: Mapping[str, Any],
        *,
        run_id: str,
        artifact: str = "events",
    ) -> dict[str, Any]:
        stream_key = self.key("run", run_id, artifact)
        event_record = {"timestamp": _now(), **dict(event)}

        self._touch_run(
            run_id,
            {
                "last_event": event_record.get("event", ""),
                "last_event_at": event_record.get("timestamp", ""),
                "event_stream_key": stream_key,
            },
        )
        self.client.sadd(self.key("run", run_id, "artifacts"), artifact)
        self.client.xadd(stream_key, _mapping(event_record))

        return {
            "backend": "redis",
            "run_id": run_id,
            "artifact": artifact,
            "key": stream_key,
            "rows": 1,
        }


def _redis_client() -> Any:
    try:
        import redis
    except ImportError as exc:
        raise StorageError(
            "STORAGE_BACKEND=redis requires the redis Python package. "
            "Install models/requirements.txt or run: pip install redis"
        ) from exc

    redis_url = os.getenv("REDIS_URL", DEFAULT_REDIS_URL)
    try:
        client = redis.Redis.from_url(redis_url, decode_responses=True)
        client.ping()
    except Exception as exc:  # pragma: no cover - depends on local Redis state.
        raise StorageError(f"cannot connect to Redis at {redis_url}: {exc}") from exc
    return client


def _store() -> RedisStore:
    backend = storage_backend()
    if backend != "redis":
        raise StorageError(f"unsupported STORAGE_BACKEND={backend!r}; expected redis or none")
    return RedisStore(_redis_client(), prefix=os.getenv("STORAGE_KEY_PREFIX", DEFAULT_PREFIX))


def _persist(operation: Callable[[RedisStore], dict[str, Any]]) -> dict[str, Any] | None:
    if not storage_enabled():
        return None
    try:
        return operation(_store())
    except StorageError:
        if storage_fail_open():
            _warn("storage is enabled but persistence failed; continuing because STORAGE_FAIL_OPEN=1")
            return None
        raise
    except Exception as exc:
        if storage_fail_open():
            _warn(f"storage is enabled but persistence failed; continuing: {exc}")
            return None
        raise StorageError(str(exc)) from exc


def persist_feature_frame(frame: Any, **kwargs: Any) -> dict[str, Any] | None:
    return _persist(lambda store: store.save_feature_frame(frame, **kwargs))


def persist_decision_report(report: Mapping[str, Any], **kwargs: Any) -> dict[str, Any] | None:
    return _persist(lambda store: store.save_decision_report(report, **kwargs))


def persist_defense_actions(actions: Iterable[Mapping[str, Any]], **kwargs: Any) -> dict[str, Any] | None:
    return _persist(lambda store: store.save_defense_actions(actions, **kwargs))


def persist_demo_summary(summary: Mapping[str, Any], **kwargs: Any) -> dict[str, Any] | None:
    return _persist(lambda store: store.save_demo_summary(summary, **kwargs))


def persist_live_feature_rows(rows: Iterable[Mapping[str, Any]], **kwargs: Any) -> dict[str, Any] | None:
    return _persist(lambda store: store.append_live_feature_rows(rows, **kwargs))


def persist_live_event(event: Mapping[str, Any], **kwargs: Any) -> dict[str, Any] | None:
    return _persist(lambda store: store.append_live_event(event, **kwargs))
