"""Generic idempotency client. HTTP and database wrappers call `once`."""

import os
import time
import uuid
from typing import Any, Callable

from agent_idempotency.audit import write_claim
from agent_idempotency.canonical import (
    canonical_dumps,
    error_envelope,
    operation_id,
    resource_key,
    success_envelope,
    token_for,
    token_for_repo,
)
from agent_idempotency.crypto import decrypt, encrypt, parse_record_key
from agent_idempotency.errors import (
    Blocked,
    CanonicalError,
    ConfigError,
    ConfirmedRollback,
    IdempotencyError,
    InProgressCleared,
    NonserializableResult,
    NotApplied,
    OversizedResult,
    RedisUnavailable,
    ReplayError,
    StaleOwner,
    UncertainOutcome,
    WaiterTimeout,
)
from agent_idempotency.redact import redact
from agent_idempotency.scope import GitScope
from agent_idempotency.store import RedisStore

_PENDING = object()
_CONTRACT_KINDS = {"value", "http_response", "db_result"}


class Client:
    """Claims one Redis key for a scope and an operation, then replays the stored outcome."""

    def __init__(
        self,
        store,
        scope_source,
        *,
        record_ttl_seconds: int = 86400,
        lock_ttl_ms: int = 120_000,
        wait_ms: int = 120_000,
        poll_ms: int = 100,
        max_result_bytes: int = 65536,
        record_key: bytes | None = None,
        require_tls: bool = False,
        redis_url: str = "",
        transport=None,
    ):
        self.store = store
        self.scope_source = scope_source
        self.record_ttl_seconds = record_ttl_seconds
        self.lock_ttl_ms = lock_ttl_ms
        self.wait_ms = wait_ms
        self.poll_ms = poll_ms
        self.max_result_bytes = max_result_bytes
        self.record_key = record_key
        self.require_tls = require_tls
        self.redis_url = redis_url
        self.transport = transport

    @classmethod
    def from_env(cls, env: dict | None = None, scope_source=None):
        """Build a Redis client from the environment. Does not invent a scope."""
        env = os.environ if env is None else env
        url = env.get("IDEMPOTENCY_REDIS_URL", "")
        if not url:
            raise ConfigError("IDEMPOTENCY_REDIS_URL is required")
        require_tls = env.get("IDEMPOTENCY_REQUIRE_TLS", "") == "1"
        if require_tls and not url.startswith("rediss://"):
            raise ConfigError("IDEMPOTENCY_REQUIRE_TLS refuses a non-rediss URL")
        return cls(
            RedisStore(url),
            scope_source or GitScope(),
            record_ttl_seconds=int(env.get("IDEMPOTENCY_RECORD_TTL_SECONDS", "86400")),
            lock_ttl_ms=int(env.get("IDEMPOTENCY_LOCK_TTL_MS", "120000")),
            wait_ms=int(env.get("IDEMPOTENCY_WAIT_MS", "120000")),
            poll_ms=int(env.get("IDEMPOTENCY_POLL_MS", "100")),
            max_result_bytes=int(env.get("IDEMPOTENCY_MAX_RESULT_BYTES", "65536")),
            record_key=parse_record_key(env.get("IDEMPOTENCY_RECORD_KEY")),
            require_tls=require_tls,
            redis_url=url,
        )

    def once(self, document: dict, run: Callable[[], dict]) -> dict:
        """Run `run` at most once for this scope and document. Replay returns the stored body."""
        scope = self.scope_source.current()
        self._guard_config()
        op_id = operation_id(document)
        repo_wide = document.get("repo_wide", False)
        if repo_wide:
            repo_id = scope.get("repo_id", "")
            if not repo_id:
                raise CanonicalError("repo_wide requires repo_id in scope")
            tok = token_for_repo(repo_id, op_id)
        else:
            tok = token_for(scope["scope_id"], op_id)
        owner = uuid.uuid4().hex
        claimed = self._store(
            "claim",
            tok,
            owner=owner,
            body=canonical_dumps({"operation_id": op_id, "scope_id": scope["scope_id"]}),
        )
        if claimed.get("status") == "corrupt":
            raise RedisUnavailable("idempotency record is corrupt")
        rk = resource_key(document)
        if claimed.get("status") != "claimed":
            write_claim(
                agent_id=scope.get("agent_id", ""),
                scope_id=scope["scope_id"],
                operation_id=op_id,
                outcome="replayed",
                repo_wide=repo_wide,
            )
            return self._follow_existing(tok, claimed)
        record = claimed["record"]
        write_claim(
            agent_id=scope.get("agent_id", ""),
            scope_id=scope["scope_id"],
            operation_id=op_id,
            outcome="sent",
            repo_wide=repo_wide,
        )
        return self._owned(tok, record["owner"], int(record["fence"]), document, run)

    def resolve_blocked(self, document: dict, *, decision: str, evidence: str, result: dict | None = None):
        """Release a blocked key, or complete it with a contract result that fits."""
        cleaned = evidence.strip()
        if decision not in {"release", "complete"}:
            raise CanonicalError("resolve decision must be release or complete")
        if not cleaned:
            raise CanonicalError("evidence is required")
        scope = self.scope_source.current()
        self._guard_config()
        op_id = operation_id(document)
        tok = token_for(scope["scope_id"], op_id)
        result_json = ""
        if decision == "complete":
            envelope = success_envelope(self._contract(result))
            self._check_size(envelope)
            result_json = canonical_dumps(encrypt(self.record_key, tok, envelope))
        body = canonical_dumps(
            {
                "decision": decision,
                "evidence": cleaned,
                "result_json": result_json,
                "scope_id": scope["scope_id"],
            }
        )
        done = self._store("resolve", tok, body=body)
        if decision == "release":
            if done.get("status") != "released":
                raise self._status_error(done)
            return None
        if done.get("status") != "completed":
            raise self._status_error(done)
        return result

    def _owned(self, tok: str, owner: str, fence: int, document: dict, run: Callable[[], dict]) -> dict:
        dispatched = False
        try:
            snapshot = canonical_dumps(encrypt(self.record_key, tok, redact(document)))
            marked = self._store("mark_dispatched", tok, owner=owner, fence=fence, body=snapshot)
            if marked.get("status") != "marked":
                raise self._status_error(marked)
            dispatched = True
            contract = self._contract(run())
            envelope = success_envelope(contract)
            self._check_size(envelope)
            stored = canonical_dumps(encrypt(self.record_key, tok, envelope))
            done = self._store("complete", tok, owner=owner, fence=fence, body=stored)
            if done.get("status") != "completed":
                raise self._status_error(done)
            return contract
        except NotApplied:
            self._clear(dispatched, tok, owner, fence)
            raise
        except ConfirmedRollback as exc:
            self._store_rollback(tok, owner, fence, exc)
            raise ReplayError("rolled_back", str(exc)[:500]) from exc
        except OversizedResult:
            self._block(tok, owner, fence, "oversized_result")
            raise
        except NonserializableResult:
            self._block(tok, owner, fence, "nonserializable_result")
            raise
        except UncertainOutcome as exc:
            self._block(tok, owner, fence, exc.reason)
            raise Blocked(exc.reason) from exc
        except (Blocked, ReplayError, RedisUnavailable, StaleOwner):
            raise
        except Exception as exc:
            if not dispatched:
                self._clear(False, tok, owner, fence)
                raise
            self._block(tok, owner, fence, "uncertain_exception")
            raise Blocked("uncertain_exception") from exc

    def _store_rollback(self, tok: str, owner: str, fence: int, exc: ConfirmedRollback) -> None:
        envelope = error_envelope("rolled_back", str(exc))
        self._check_size(envelope)
        stored = canonical_dumps(encrypt(self.record_key, tok, envelope))
        done = self._store("complete", tok, owner=owner, fence=fence, body=stored)
        if done.get("status") != "completed":
            raise self._status_error(done)

    def _follow_existing(self, tok: str, claimed: dict) -> dict:
        status = claimed.get("status")
        if status == "completed":
            return self._replay(tok, claimed.get("record"))
        if status == "blocked":
            raise self._blocked(claimed.get("record"))
        if status == "in_progress":
            return self._wait(tok)
        raise RedisUnavailable(f"unexpected claim status {status}")

    def _wait(self, tok: str) -> dict:
        deadline = time.monotonic() + (self.wait_ms / 1000)
        while True:
            step = self._wait_step(tok, self._store("read", tok))
            if step is not _PENDING:
                return step
            if time.monotonic() >= deadline:
                step = self._wait_step(tok, self._store("read", tok))
                if step is _PENDING:
                    raise WaiterTimeout("in-progress record was still in progress when the wait bound ended")
                return step
            time.sleep(self.poll_ms / 1000)

    def _wait_step(self, tok: str, current: dict):
        status = current.get("status")
        if status == "completed":
            return self._replay(tok, current.get("record"))
        if status == "blocked":
            raise self._blocked(current.get("record"))
        if status == "empty":
            raise InProgressCleared("the in-progress record disappeared before completion")
        if status == "corrupt":
            raise RedisUnavailable("idempotency record is corrupt")
        if status == "in_progress":
            return _PENDING
        raise RedisUnavailable(f"unexpected record status {status}")

    def _replay(self, tok: str, record: Any) -> dict:
        if not isinstance(record, dict) or not isinstance(record.get("result"), dict):
            raise ReplayError("replay_undecodable", "stored result is missing")
        try:
            opened = decrypt(self.record_key, tok, record["result"])
        except Exception as exc:
            raise ReplayError("replay_undecodable", "stored result cannot be opened") from exc
        outcome = opened.get("outcome")
        if outcome == "success":
            return opened["body"]
        if outcome == "error":
            body = opened.get("body") or {}
            raise ReplayError(str(body.get("code") or "replay_error"), str(body.get("message") or ""))
        raise ReplayError("replay_undecodable", "stored result is not an envelope")

    def _clear(self, dispatched: bool, tok: str, owner: str, fence: int) -> None:
        op = "release_not_applied" if dispatched else "abort"
        try:
            self._store(op, tok, owner=owner, fence=fence)
        except IdempotencyError:
            return

    def _block(self, tok: str, owner: str, fence: int, reason: str) -> None:
        try:
            self._store("block", tok, owner=owner, fence=fence, body=canonical_dumps({"reason": reason}))
        except IdempotencyError:
            return

    def _store(self, op: str, token: str, *, owner: str = "", fence: int = 0, body: str = "") -> dict:
        try:
            return self.store.call(
                op,
                token,
                owner=owner,
                fence=fence,
                lock_ttl_ms=self.lock_ttl_ms,
                record_ttl_seconds=self.record_ttl_seconds,
                max_bytes=self.max_result_bytes * 2 + 4096,
                body=body,
            )
        except RedisUnavailable:
            raise
        except Exception as exc:
            raise RedisUnavailable(str(exc)) from exc

    def _guard_config(self) -> None:
        if self.require_tls and not self.redis_url.startswith("rediss://"):
            raise ConfigError("IDEMPOTENCY_REQUIRE_TLS refuses a non-rediss URL")

    def _check_size(self, envelope: dict) -> None:
        if len(canonical_dumps(envelope).encode("utf-8")) > self.max_result_bytes:
            raise OversizedResult("result exceeds the serialization contract")

    def _contract(self, value: Any) -> dict:
        if not isinstance(value, dict) or value.get("kind") not in _CONTRACT_KINDS:
            raise NonserializableResult("result is outside the serialization contract")
        try:
            canonical_dumps(value)
        except CanonicalError as exc:
            raise NonserializableResult(str(exc)) from exc
        return value

    def _blocked(self, record: Any) -> Blocked:
        reason = "blocked"
        if isinstance(record, dict) and record.get("reason"):
            reason = str(record["reason"])
        return Blocked(reason)

    def _status_error(self, payload: dict) -> IdempotencyError:
        status = payload.get("status")
        record = payload.get("record") if isinstance(payload.get("record"), dict) else {}
        if status == "blocked":
            return self._blocked(record)
        if status == "stale_owner":
            return StaleOwner("a newer owner holds this idempotency record")
        if status == "corrupt":
            return RedisUnavailable("idempotency record is corrupt")
        reason = record.get("reason") if isinstance(record, dict) else None
        if reason:
            return Blocked(str(reason))
        return RedisUnavailable(f"idempotency transition was {status}")
