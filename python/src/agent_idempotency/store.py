"""Redis record store and an in-process store with the same transitions."""

import copy
import json
import threading
import time
from importlib.resources import files
from typing import Any

from agent_idempotency.canonical import fence_key, redis_key
from agent_idempotency.errors import RedisUnavailable


def lua_script() -> str:
    resource = files("agent_idempotency").joinpath("redis", "record.lua")
    return resource.read_text(encoding="utf-8")


class MemoryStore:
    """Single-process stand-in for the Lua transitions. `now_ms` is injectable."""

    def __init__(self):
        self.now_ms: int | None = None
        self._keys: dict[str, dict[str, Any]] = {}
        self._fences: dict[str, dict[str, int]] = {}
        self._lock = threading.Lock()

    def call(
        self,
        op: str,
        token: str,
        *,
        owner: str = "",
        fence: int | str = 0,
        lock_ttl_ms: int = 120_000,
        record_ttl_seconds: int = 86400,
        max_bytes: int = 65536,
        body: str = "",
    ) -> dict:
        with self._lock:
            return self._call(op, token, owner, fence, lock_ttl_ms, record_ttl_seconds, max_bytes, body)

    def peek(self, token: str) -> dict | None:
        with self._lock:
            slot = self._keys.get(token)
            if slot is None or self._clock() >= slot["expires_at"]:
                return None
            return copy.deepcopy(slot["record"])

    def _clock(self) -> int:
        if self.now_ms is None:
            return int(time.time() * 1000)
        return self.now_ms

    def _call(self, op, token, owner, fence, lock_ttl_ms, record_ttl_seconds, max_bytes, body) -> dict:
        now = self._clock()
        rec = self._live(token, now)
        if op == "claim":
            if rec is None:
                payload = self._decode(body)
                if payload is None:
                    return {"status": "rejected", "record": None}
                fence_n = self._next_fence(token, now, record_ttl_seconds)
                rec = {
                    "v": 1,
                    "state": "in_progress",
                    "dispatched": False,
                    "scope_id": payload["scope_id"],
                    "operation_id": payload["operation_id"],
                    "owner": owner,
                    "fence": fence_n,
                    "lock_expires_at_ms": now + lock_ttl_ms,
                    "snapshot": None,
                    "result": None,
                    "reason": None,
                }
                self._keys[token] = {"record": rec, "expires_at": now + record_ttl_seconds * 1000}
                return {"status": "claimed", "record": copy.deepcopy(rec)}
            return {"status": _public_state(rec), "record": copy.deepcopy(rec)}
        if rec is None:
            return {"status": "empty", "record": None}
        if op == "read":
            return {"status": _public_state(rec), "record": copy.deepcopy(rec)}
        if op == "resolve":
            return self._resolve(token, rec, max_bytes, body)
        if not _same_owner(rec, owner, fence):
            return {"status": "stale_owner", "record": copy.deepcopy(rec)}
        if rec["state"] == "blocked":
            return {"status": "blocked", "record": copy.deepcopy(rec)}
        if rec["state"] != "in_progress":
            return {"status": "rejected", "record": copy.deepcopy(rec)}
        if op == "mark_dispatched":
            if rec["dispatched"]:
                return {"status": "rejected", "record": copy.deepcopy(rec)}
            if body:
                payload = self._decode(body)
                if payload is None:
                    return {"status": "rejected", "record": copy.deepcopy(rec)}
                rec["snapshot"] = payload
            rec["dispatched"] = True
            return {"status": "marked", "record": copy.deepcopy(rec)}
        if op == "abort":
            if rec["dispatched"]:
                return {"status": "rejected", "record": copy.deepcopy(rec)}
            del self._keys[token]
            return {"status": "aborted", "record": None}
        if op == "release_not_applied":
            if not rec["dispatched"]:
                return {"status": "rejected", "record": copy.deepcopy(rec)}
            del self._keys[token]
            return {"status": "released", "record": None}
        if op == "block":
            payload = self._decode(body)
            if payload is None or not isinstance(payload.get("reason"), str):
                return {"status": "rejected", "record": copy.deepcopy(rec)}
            rec["state"] = "blocked"
            rec["reason"] = payload["reason"]
            rec["lock_expires_at_ms"] = None
            rec["result"] = None
            return {"status": "blocked", "record": copy.deepcopy(rec)}
        if op == "complete":
            if not rec["dispatched"]:
                return {"status": "rejected", "record": copy.deepcopy(rec)}
            if len(body.encode("utf-8")) > max_bytes:
                rec["state"] = "blocked"
                rec["reason"] = "oversized_result"
                rec["lock_expires_at_ms"] = None
                rec["result"] = None
                return {"status": "blocked", "record": copy.deepcopy(rec)}
            payload = self._decode(body)
            if payload is None:
                return {"status": "rejected", "record": copy.deepcopy(rec)}
            rec["state"] = "completed"
            rec["reason"] = None
            rec["lock_expires_at_ms"] = None
            rec["result"] = payload
            return {"status": "completed", "record": copy.deepcopy(rec)}
        return {"status": "rejected", "record": copy.deepcopy(rec)}

    def _resolve(self, token: str, rec: dict, max_bytes: int, body: str) -> dict:
        if rec["state"] != "blocked":
            return {"status": "rejected", "record": copy.deepcopy(rec)}
        payload = self._decode(body)
        if payload is None:
            return {"status": "rejected", "record": copy.deepcopy(rec)}
        evidence = payload.get("evidence")
        if payload.get("scope_id") != rec["scope_id"] or not isinstance(evidence, str) or evidence == "":
            return {"status": "rejected", "record": copy.deepcopy(rec)}
        if payload.get("decision") == "release":
            del self._keys[token]
            return {"status": "released", "record": None}
        result_json = payload.get("result_json")
        if payload.get("decision") != "complete" or not isinstance(result_json, str):
            return {"status": "rejected", "record": copy.deepcopy(rec)}
        if len(result_json.encode("utf-8")) > max_bytes:
            return {"status": "rejected", "record": copy.deepcopy(rec)}
        try:
            result = json.loads(result_json)
        except json.JSONDecodeError:
            return {"status": "rejected", "record": copy.deepcopy(rec)}
        rec["state"] = "completed"
        rec["reason"] = None
        rec["result"] = result
        rec["evidence"] = evidence
        return {"status": "completed", "record": copy.deepcopy(rec)}

    def _live(self, token: str, now: int) -> dict | None:
        slot = self._keys.get(token)
        if slot is None:
            return None
        if now >= slot["expires_at"]:
            del self._keys[token]
            return None
        rec = slot["record"]
        lock_at = rec.get("lock_expires_at_ms")
        if rec["state"] == "in_progress" and isinstance(lock_at, int) and lock_at <= now:
            rec["state"] = "blocked"
            rec["reason"] = "lock_expired"
            rec["lock_expires_at_ms"] = None
        return rec

    def _next_fence(self, token: str, now: int, record_ttl_seconds: int) -> int:
        slot = self._fences.get(token)
        if slot is None or now >= slot["expires_at"]:
            value = 0
        else:
            value = slot["value"]
        value += 1
        self._fences[token] = {"value": value, "expires_at": now + record_ttl_seconds * 1000}
        return value

    def _decode(self, body: str) -> dict | None:
        if not body:
            return {}
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        return payload


class RedisStore:
    """Atomic transitions through the packaged `record.lua`."""

    def __init__(self, url: str, client=None):
        import redis

        self._redis = client or redis.Redis.from_url(
            url,
            decode_responses=True,
            socket_connect_timeout=0.4,
            socket_timeout=5,
        )
        self._script = lua_script()

    def call(
        self,
        op: str,
        token: str,
        *,
        owner: str = "",
        fence: int | str = 0,
        lock_ttl_ms: int = 120_000,
        record_ttl_seconds: int = 86400,
        max_bytes: int = 65536,
        body: str = "",
    ) -> dict:
        import redis

        try:
            raw = self._redis.eval(
                self._script,
                2,
                redis_key(token),
                fence_key(token),
                op,
                owner,
                str(fence),
                str(lock_ttl_ms),
                str(record_ttl_seconds),
                str(max_bytes),
                body or "",
            )
        except redis.RedisError as exc:
            raise RedisUnavailable(str(exc)) from exc
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RedisUnavailable("redis returned a non-json record") from exc
        if not isinstance(parsed, dict):
            raise RedisUnavailable("redis returned an unexpected record")
        return parsed

    def peek(self, token: str) -> dict | None:
        import redis

        try:
            raw = self._redis.get(redis_key(token))
        except redis.RedisError as exc:
            raise RedisUnavailable(str(exc)) from exc
        if raw is None:
            return None
        return json.loads(raw)


def _same_owner(rec: dict, owner: str, fence: int | str) -> bool:
    try:
        return rec.get("owner") == owner and int(rec.get("fence")) == int(fence)
    except (TypeError, ValueError):
        return False


def _public_state(rec: dict) -> str:
    if rec["state"] == "completed":
        return "completed"
    if rec["state"] == "blocked":
        return "blocked"
    return "in_progress"
