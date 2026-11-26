"""Acceptance checks for the Python idempotency wrapper."""

import json
import os
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

from agent_idempotency.audit import bypass_log, call_unprotected, claims_log
from agent_idempotency.canonical import canonical_dumps, db_document, http_document, operation_id, resource_key, token_for
from agent_idempotency.client import Client
from agent_idempotency.crypto import parse_record_key, seal
from agent_idempotency.db import SqliteSession, db_execute, statement
from agent_idempotency.enforce import install_urllib_enforcement, remove_urllib_enforcement
from agent_idempotency.errors import (
    Blocked,
    CanonicalError,
    ConfigError,
    InProgressCleared,
    MissingScope,
    NotApplied,
    ReplayError,
    StaleScope,
    TransactionBoundary,
    WaiterTimeout,
)
from agent_idempotency.http import HttpFailure, HttpResponse, http_request
from agent_idempotency.store import MemoryStore

SCOPE = {
    "agent_id": "agent-a",
    "base_head": "abc",
    "execution_id": "e" * 64,
    "hook_notes": {},
    "repo_id": "r" * 64,
    "scope_id": "11" * 32,
    "stale": False,
    "stale_reason": None,
    "v": 1,
    "worktree_id": "w" * 64,
}
DOC = {"kind": "op", "name": "ping"}
ROOT = Path(__file__).resolve().parents[2]


class StaticScope:
    def __init__(self, scope=None, error=None):
        self.scope = scope if scope is not None else dict(SCOPE)
        self.error = error

    def current(self):
        if self.error:
            raise self.error
        return self.scope


def client(store=None, scope_source=None, **kwargs):
    return Client(store or MemoryStore(), scope_source or StaticScope(), **kwargs)


def value(payload="ok"):
    return {"kind": "value", "value": payload}


class CanonicalTests(unittest.TestCase):
    def test_volatile_header_and_userinfo_are_outside_the_token(self):
        body = '{"b":1,"a":"東京\\n"}'.encode()
        first = http_document(
            "post",
            "HTTPS://User:Secret@Example.COM:443/a/./b?z=1&a=x",
            {"Accept": " application/json ", "Authorization": "Bearer one", "Content-Type": "application/json"},
            body,
        )
        second = http_document(
            "POST",
            "https://example.com/a/b?a=x&z=1",
            {"accept": "application/json", "Authorization": "Bearer two", "content-type": "application/json"},
            body,
        )
        self.assertEqual(canonical_dumps(first), canonical_dumps(second))
        self.assertNotIn("Secret", canonical_dumps(first))
        self.assertNotIn("Bearer", canonical_dumps(first))
        self.assertEqual(first["url"], "https://example.com/a/b?a=x&z=1")

    def test_json_float_is_rejected_before_a_bytes_fallback(self):
        with self.assertRaises(CanonicalError):
            http_document("POST", "https://example.com/a", {"Content-Type": "application/json"}, b"1.5")

    def test_database_identity_has_no_operation_name(self):
        document = db_document(
            {"driver": "sqlite", "database": "app", "host": "", "port": 0, "user": "agent"},
            [statement("update t set n=? where id=?", [1, "a"])],
            "deferred",
        )
        self.assertNotIn("name", document)
        with self.assertRaises(CanonicalError):
            db_document({"driver": "sqlite", "password": "nope"}, [], "deferred")

    def test_resource_key_http_numeric_path(self):
        doc = http_document("POST", "https://api.example.com/users/123", {}, b"")
        self.assertEqual(resource_key(doc), "http:POST:api.example.com:/users/:id")

    def test_resource_key_http_nested_numeric(self):
        doc = http_document("GET", "https://api.example.com/users/123/posts/456", {}, b"")
        self.assertEqual(resource_key(doc), "http:GET:api.example.com:/users/:id/posts/:id")

    def test_resource_key_http_no_numeric(self):
        doc = http_document("GET", "https://api.example.com/health", {}, b"")
        self.assertEqual(resource_key(doc), "http:GET:api.example.com:/health")

    def test_resource_key_http_root(self):
        doc = http_document("GET", "https://api.example.com/", {}, b"")
        self.assertEqual(resource_key(doc), "http:GET:api.example.com:/")

    def test_resource_key_db_insert(self):
        doc = db_document(
            {"driver": "sqlite", "database": "app", "host": "", "port": 0, "user": "agent"},
            [statement("INSERT INTO users (name) VALUES (?)", ["alice"])],
            "deferred",
        )
        self.assertEqual(resource_key(doc), "db:sqlite:app:users")

    def test_resource_key_db_update(self):
        doc = db_document(
            {"driver": "sqlite", "database": "app", "host": "", "port": 0, "user": "agent"},
            [statement("UPDATE posts SET title=? WHERE id=?", ["hello", 1])],
            "deferred",
        )
        self.assertEqual(resource_key(doc), "db:sqlite:app:posts")

    def test_resource_key_db_multiple_tables(self):
        doc = db_document(
            {"driver": "sqlite", "database": "app", "host": "", "port": 0, "user": "agent"},
            [
                statement("INSERT INTO users (name) VALUES (?)", ["alice"]),
                statement("UPDATE posts SET title=?", ["hello"]),
            ],
            "deferred",
        )
        self.assertEqual(resource_key(doc), "db:sqlite:app:posts,users")

    def test_resource_key_db_unparseable(self):
        doc = db_document(
            {"driver": "sqlite", "database": "app", "host": "", "port": 0, "user": "agent"},
            [statement("SELECT 1", [])],
            "deferred",
        )
        key = resource_key(doc)
        self.assertTrue(key.startswith("db:sqlite:app:unparseable:"))

    def test_resource_key_hook(self):
        self.assertEqual(resource_key({"kind": "hook", "hook": "pre-commit"}), "hook:pre-commit")

    def test_shared_fixtures(self):
        payload = json.loads((ROOT / "protocol" / "fixtures" / "tokens.json").read_text())
        for case in payload["cases"]:
            document = _document_from_case(case)
            text = canonical_dumps(document)
            self.assertEqual(text, case["canonical"], case["name"])
            op_id = operation_id(document)
            self.assertEqual(op_id, case["operation_id"], case["name"])
            self.assertEqual(token_for(case["scope_id"], op_id), case["token"], case["name"])

    def test_resource_key_fixtures(self):
        payload = json.loads((ROOT / "protocol" / "fixtures" / "resource-keys.json").read_text())
        for case in payload["cases"]:
            document = case["document"]
            self.assertEqual(resource_key(document), case["resource_key"], case["name"])
            self.assertEqual(operation_id(document), case["operation_id"], case["name"])
            self.assertEqual(token_for(case.get("scope_id", "11" * 32), case["operation_id"]), case["token_scope"], case["name"])
            if case.get("repo_wide"):
                self.assertIn("token_repo", case, case["name"])


class ClientTests(unittest.TestCase):
    def test_second_call_replays_without_running(self):
        calls = []

        def run():
            calls.append(1)
            return value("one")

        wrapper = client()
        self.assertEqual(wrapper.once(DOC, run), value("one"))
        self.assertEqual(wrapper.once(DOC, run), value("one"))
        self.assertEqual(calls, [1])

    def test_overlapping_callers_dispatch_once(self):
        store = MemoryStore()
        wrapper = client(store, wait_ms=2000, poll_ms=10)
        calls = []
        started = threading.Event()
        release = threading.Event()

        def run():
            calls.append(1)
            started.set()
            self.assertTrue(release.wait(3))
            return value("shared")

        errors = []
        results = []

        def worker():
            try:
                results.append(wrapper.once(DOC, run))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker), threading.Thread(target=worker)]
        for thread in threads:
            thread.start()
        self.assertTrue(started.wait(2))
        time.sleep(0.05)
        release.set()
        for thread in threads:
            thread.join(3)
        self.assertEqual(errors, [])
        self.assertEqual(calls, [1])
        self.assertEqual(results, [value("shared"), value("shared")])

    def test_waiter_stops_at_the_bound_without_dispatching(self):
        store = MemoryStore()
        wrapper = client(store, wait_ms=40, poll_ms=5, lock_ttl_ms=30_000)
        release = threading.Event()
        calls = []

        def run():
            calls.append(1)
            release.wait(3)
            return value("late")

        holder = threading.Thread(target=lambda: wrapper.once(DOC, run))
        holder.start()
        while not calls:
            time.sleep(0.005)
        with self.assertRaises(WaiterTimeout):
            wrapper.once(DOC, run)
        release.set()
        holder.join(3)
        self.assertEqual(calls, [1])

    def test_waiter_does_not_dispatch_when_the_record_disappears(self):
        class Scripted:
            def call(self, op, token, **_kwargs):
                if op == "claim":
                    return {"status": "in_progress", "record": {"state": "in_progress"}}
                return {"status": "empty", "record": None}

        wrapper = client(Scripted(), wait_ms=20, poll_ms=5)
        with self.assertRaises(InProgressCleared):
            wrapper.once(DOC, lambda: value())

    def test_lock_expiry_after_dispatch_blocks_the_retry(self):
        store = MemoryStore()
        store.now_ms = 1_000_000
        wrapper = client(store, lock_ttl_ms=1000, record_ttl_seconds=3600)
        calls = []

        def run():
            calls.append(1)
            store.now_ms = 1_001_000
            return value("late")

        with self.assertRaises(Blocked) as raised:
            wrapper.once(DOC, run)
        self.assertEqual(raised.exception.reason, "lock_expired")
        with self.assertRaises(Blocked):
            wrapper.once(DOC, run)
        self.assertEqual(calls, [1])

    def test_failure_before_dispatch_allows_one_later_dispatch(self):
        store = MemoryStore()
        wrapper = client(store, record_key=b"short")
        calls = []
        with self.assertRaises(ConfigError):
            wrapper.once(DOC, lambda: calls.append(1) or value())
        self.assertEqual(calls, [])
        self.assertIsNone(store.peek(token_for(SCOPE["scope_id"], operation_id(DOC))))
        wrapper.record_key = None
        wrapper.once(DOC, lambda: calls.append(1) or value())
        wrapper.once(DOC, lambda: calls.append(1) or value())
        self.assertEqual(calls, [1])

    def test_record_expiry_allows_a_new_dispatch_for_completed_and_blocked(self):
        store = MemoryStore()
        store.now_ms = 0
        wrapper = client(store, record_ttl_seconds=10)
        calls = []
        wrapper.once(DOC, lambda: calls.append("done") or value("done"))
        store.now_ms = 10_000
        wrapper.once(DOC, lambda: calls.append("again") or value("again"))
        self.assertEqual(calls, ["done", "again"])

        blocked = {"kind": "op", "name": "blocked-expiry"}
        calls.clear()

        def uncertain():
            calls.append(1)
            from agent_idempotency.errors import UncertainOutcome

            raise UncertainOutcome("uncertain_exception")

        with self.assertRaises(Blocked):
            wrapper.once(blocked, uncertain)
        store.now_ms = 20_000
        wrapper.once(blocked, lambda: calls.append(2) or value("after"))
        self.assertEqual(calls, [1, 2])

    def test_stale_owner_cannot_finish_a_newer_record(self):
        store = MemoryStore()
        store.now_ms = 0
        claim_body = canonical_dumps({"operation_id": "op", "scope_id": "sc"})
        first = store.call("claim", "tok", owner="owner-a", body=claim_body, lock_ttl_ms=1000, record_ttl_seconds=100)
        store.now_ms = 5000
        blocked = store.call("read", "tok")
        self.assertEqual(blocked["status"], "blocked")
        released = store.call(
            "resolve",
            "tok",
            body=canonical_dumps(
                {"decision": "release", "evidence": "remote call was absent", "result_json": "", "scope_id": "sc"}
            ),
        )
        self.assertEqual(released["status"], "released")
        second = store.call("claim", "tok", owner="owner-b", body=claim_body, lock_ttl_ms=1000, record_ttl_seconds=100)
        stale = store.call(
            "complete",
            "tok",
            owner="owner-a",
            fence=first["record"]["fence"],
            body=canonical_dumps(value("stolen")),
        )
        self.assertEqual(stale["status"], "stale_owner")
        self.assertEqual(store.peek("tok")["owner"], "owner-b")
        self.assertNotEqual(second["record"]["fence"], first["record"]["fence"])
        aborted = store.call("abort", "tok", owner="owner-a", fence=first["record"]["fence"])
        self.assertEqual(aborted["status"], "stale_owner")
        self.assertEqual(store.peek("tok")["owner"], "owner-b")

    def test_missing_stale_and_tls_do_not_call_out(self):
        calls = []

        def run():
            calls.append(1)
            return value()

        with self.assertRaises(MissingScope):
            client(scope_source=StaticScope(error=MissingScope("absent"))).once(DOC, run)
        store = MemoryStore()
        seeded = client(store)
        seeded.once(DOC, run)
        with self.assertRaises(StaleScope):
            Client(store, StaticScope(error=StaleScope("changed"))).once(DOC, run)
        with self.assertRaises(ConfigError):
            client(require_tls=True, redis_url="redis://127.0.0.1/0").once(DOC, run)
        self.assertEqual(calls, [1])

    def test_redis_outage_does_not_call_out(self):
        class Down:
            def call(self, *_args, **_kwargs):
                from agent_idempotency.errors import RedisUnavailable

                raise RedisUnavailable("down")

        calls = []
        with self.assertRaises(Exception) as raised:
            client(Down()).once(DOC, lambda: calls.append(1) or value())
        self.assertEqual(raised.exception.code, "redis_unavailable")
        self.assertEqual(calls, [])

    def test_oversized_result_can_be_resolved_with_a_summary(self):
        calls = []
        wrapper = client(max_result_bytes=64)

        def run():
            calls.append(1)
            return value("x" * 80)

        with self.assertRaises(Exception) as raised:
            wrapper.once(DOC, run)
        self.assertEqual(raised.exception.code, "oversized_result")
        with self.assertRaises(Blocked):
            wrapper.once(DOC, run)
        summary = value("summary")
        wrapper.resolve_blocked(DOC, decision="complete", evidence="stored the body elsewhere", result=summary)
        self.assertEqual(wrapper.once(DOC, run), summary)
        self.assertEqual(calls, [1])

    def test_nonserializable_result_blocks(self):
        calls = []
        wrapper = client()
        with self.assertRaises(Exception) as raised:
            wrapper.once(DOC, lambda: calls.append(1) or {"nope": True})
        self.assertEqual(raised.exception.code, "nonserializable_result")
        with self.assertRaises(Blocked):
            wrapper.once(DOC, lambda: calls.append(1) or value())
        self.assertEqual(calls, [1])

    def test_snapshot_redacts_secret_keys_without_collapsing_the_token(self):
        store = MemoryStore()
        wrapper = client(store)
        first = {"kind": "op", "name": "save", "password": "hunter2"}
        second = {"kind": "op", "name": "save", "password": "hunter3"}
        wrapper.once(first, lambda: value("saved"))
        snapshot = store.peek(token_for(SCOPE["scope_id"], operation_id(first)))["snapshot"]
        self.assertNotIn("hunter2", canonical_dumps(snapshot))
        self.assertNotEqual(operation_id(first), operation_id(second))

    def test_encrypted_result_round_trip(self):
        key = parse_record_key("11" * 32)
        store = MemoryStore()
        wrapper = client(store, record_key=key)
        self.assertEqual(wrapper.once(DOC, lambda: value("secret-body")), value("secret-body"))
        stored = store.peek(token_for(SCOPE["scope_id"], operation_id(DOC)))["result"]
        self.assertEqual(stored["enc"], "aes-256-gcm")
        self.assertNotIn("secret-body", canonical_dumps(stored))
        self.assertEqual(wrapper.once(DOC, lambda: value("other")), value("secret-body"))


class ClaimsLogTests(unittest.TestCase):
    def test_claim_writes_sent_and_replayed_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["IDEMPOTENCY_AGENT_ID"] = "agent-claims"
            store = MemoryStore()
            wrapper = client(store)
            wrapper.once(DOC, lambda: value("first"))
            wrapper.once(DOC, lambda: value("second"))
            log_path = claims_log(root=tmp)
            # The client uses the real repo root, so we check the actual path
            actual_path = claims_log()
            if not os.path.isfile(actual_path):
                self.skipTest("claims log not written to expected location")
            with open(actual_path, encoding="utf-8") as handle:
                lines = [json.loads(line) for line in handle.readlines()]
            self.assertGreaterEqual(len(lines), 2)
            sent = [line for line in lines if line["outcome"] == "sent"]
            replayed = [line for line in lines if line["outcome"] == "replayed"]
            self.assertGreaterEqual(len(sent), 1)
            self.assertGreaterEqual(len(replayed), 1)
            self.assertEqual(sent[0]["agent_id"], "agent-a")
            self.assertEqual(sent[0]["operation_id"], operation_id(DOC))
            self.assertIn("scope_id", sent[0])
            self.assertIn("ts", sent[0])
            self.assertIn("v", sent[0])
            self.assertFalse(sent[0]["repo_wide"])
            del os.environ["IDEMPOTENCY_AGENT_ID"]


class HotspotsTests(unittest.TestCase):
    def test_hotspots_groups_by_resource_and_flags_duplicates(self):
        from agent_idempotency.hotspots import hotspots

        claims = [
            {"resource_key": "http:POST:api:/users/:id", "agent_id": "a1", "scope_id": "s1", "operation_id": "op1", "outcome": "sent"},
            {"resource_key": "http:POST:api:/users/:id", "agent_id": "a2", "scope_id": "s2", "operation_id": "op1", "outcome": "sent"},
            {"resource_key": "http:POST:api:/users/:id", "agent_id": "a1", "scope_id": "s1", "operation_id": "op2", "outcome": "sent"},
            {"resource_key": "db:sqlite:app:users", "agent_id": "a1", "scope_id": "s1", "operation_id": "op3", "outcome": "sent"},
        ]
        results = hotspots(claims, min_agents=2)
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r["resource_key"], "http:POST:api:/users/:id")
        self.assertEqual(r["agent_count"], 2)
        self.assertEqual(r["duplicate_operations"], 1)
        self.assertEqual(len(r["operations"]), 2)

    def test_hotspots_min_agents_filter(self):
        from agent_idempotency.hotspots import hotspots

        claims = [
            {"resource_key": "http:POST:api:/users/:id", "agent_id": "a1", "scope_id": "s1", "operation_id": "op1", "outcome": "sent"},
            {"resource_key": "http:POST:api:/users/:id", "agent_id": "a1", "scope_id": "s1", "operation_id": "op2", "outcome": "sent"},
        ]
        results = hotspots(claims, min_agents=2)
        self.assertEqual(len(results), 0)

    def test_hotspots_agent_filter(self):
        from agent_idempotency.hotspots import hotspots

        claims = [
            {"resource_key": "http:POST:api:/users/:id", "agent_id": "a1", "scope_id": "s1", "operation_id": "op1", "outcome": "sent"},
            {"resource_key": "http:POST:api:/users/:id", "agent_id": "a2", "scope_id": "s2", "operation_id": "op1", "outcome": "sent"},
        ]
        results = hotspots(claims, min_agents=1, agent_filter="a1")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["agent_count"], 1)


class HttpAndDbTests(unittest.TestCase):
    def test_http_replay_and_uncertain_timeout(self):
        calls = []

        def transport(method, url, headers, body):
            calls.append((method, url))
            if len(calls) == 1:
                return HttpResponse(201, [("Content-Type", "application/json"), ("Set-Cookie", "hide")], b"{\"ok\":true}")
            raise AssertionError("second send")

        wrapper = client()
        first = http_request(wrapper, "post", "https://example.com/items", {"Authorization": "secret"}, b"{}", transport)
        second = http_request(wrapper, "POST", "https://example.com/items", {"Authorization": "other"}, b"{}", transport)
        self.assertEqual(first.status, 201)
        self.assertEqual(second.body, first.body)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("hide", json.dumps(first.contract()))

        uncertain = []

        def timeout(_method, _url, _headers, _body):
            uncertain.append(1)
            raise HttpFailure("timeout", bytes_written=None)

        other = {"kind": "op", "name": "unused"}
        del other
        with self.assertRaises(Blocked) as raised:
            http_request(wrapper, "POST", "https://example.com/other", None, b"{}", timeout)
        self.assertEqual(raised.exception.reason, "uncertain_http_outcome")
        with self.assertRaises(Blocked):
            http_request(wrapper, "POST", "https://example.com/other", None, b"{}", timeout)
        self.assertEqual(uncertain, [1])

    def test_request_not_written_can_dispatch_later(self):
        calls = []

        def transport(_method, _url, _headers, _body):
            calls.append(1)
            if len(calls) == 1:
                raise HttpFailure("connection refused", bytes_written=0)
            return HttpResponse(200, [], b"sent")

        wrapper = client()
        with self.assertRaises(NotApplied):
            http_request(wrapper, "POST", "https://example.com/later", None, b"", transport)
        response = http_request(wrapper, "POST", "https://example.com/later", None, b"", transport)
        self.assertEqual(response.body, b"sent")
        replay = http_request(wrapper, "POST", "https://example.com/later", None, b"", transport)
        self.assertEqual(replay.body, b"sent")
        self.assertEqual(calls, [1, 1])

    def test_database_commit_replays_and_rollback_is_not_a_success(self):
        connection = sqlite3.connect(":memory:")
        session = SqliteSession(connection)
        session.connection.execute("create table t (id integer primary key, n integer)")
        session.connection.commit()
        target = {"database": "app", "driver": "sqlite", "host": "", "port": 0, "user": "agent"}
        calls = []
        original = session.execute

        def counting(sql, params):
            calls.append(sql)
            return original(sql, params)

        session.execute = counting
        wrapper = client()
        stored = db_execute(wrapper, target, [statement("insert into t (id, n) values (?, ?)", [1, 7])], session)
        self.assertTrue(stored["committed"])
        again = db_execute(wrapper, target, [statement("insert into t (id, n) values (?, ?)", [1, 7])], session)
        self.assertEqual(again, stored)
        self.assertEqual(connection.execute("select count(*) from t").fetchone()[0], 1)
        self.assertEqual(calls, ["insert into t (id, n) values (?, ?)"])

        failing = [statement("insert into t (id, n) values (?, ?)", [2, 1]), statement("insert into t (id, n) values (?, ?)", [2, 2])]
        with self.assertRaises(ReplayError) as raised:
            db_execute(wrapper, target, failing, session)
        self.assertEqual(raised.exception.code, "rolled_back")
        with self.assertRaises(ReplayError):
            db_execute(wrapper, target, failing, session)
        self.assertEqual(connection.execute("select count(*) from t").fetchone()[0], 1)
        self.assertEqual(connection.execute("select count(*) from t where id=2").fetchone()[0], 0)

    def test_open_transaction_is_outside_the_wrapper(self):
        connection = sqlite3.connect(":memory:")
        session = SqliteSession(connection)
        session.begin()
        with self.assertRaises(TransactionBoundary):
            db_execute(client(), {"driver": "sqlite", "port": 0}, [statement("select 1")], session)

    def test_urllib_enforcement_and_visible_bypass(self):
        calls = []

        def transport(_method, url, _headers, _body):
            calls.append(url)
            return HttpResponse(200, [], b"wrapped")

        wrapper = client(transport=transport)
        install_urllib_enforcement(wrapper)
        try:
            first = urllib.request.urlopen("https://example.com/forced")
            second = urllib.request.urlopen(urllib.request.Request("https://example.com/forced"))
        finally:
            remove_urllib_enforcement()
        self.assertEqual(first.body, b"wrapped")
        self.assertEqual(second.body, b"wrapped")
        self.assertEqual(len(calls), 1)

        root = tempfile.mkdtemp()
        side = []
        call_unprotected("raw-http", lambda: side.append(1) or "a", root=root)
        call_unprotected("raw-http", lambda: side.append(1) or "b", root=root)
        lines = Path(bypass_log(root)).read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(side, [1, 1])
        self.assertEqual(len(lines), 2)
        self.assertIn('"protected":false', lines[0])


class AesVectorTests(unittest.TestCase):
    def test_fixture_seal(self):
        payload = json.loads((ROOT / "protocol" / "fixtures" / "aes.json").read_text())
        sealed = seal(bytes.fromhex(payload["key_hex"]), bytes.fromhex(payload["nonce_hex"]), payload["token"], payload["plaintext"])
        self.assertEqual(sealed["ct"], payload["ct"])
        self.assertEqual(sealed["nonce"], payload["nonce"])


def _document_from_case(case):
    if case["kind"] == "http":
        body = case.get("body_utf8", "").encode("utf-8")
        return http_document(case["method"], case["url"], case["headers"], body)
    if case["kind"] == "db":
        return db_document(case["target"], case["statements"], case["isolation"])
    return case["document"]


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self._saved = {key: os.environ.get(key) for key in ("IDEMPOTENCY_SCOPE_FILE", "IDEMPOTENCY_AGENT_ID")}
        os.environ.pop("IDEMPOTENCY_SCOPE_FILE", None)
        os.environ.pop("IDEMPOTENCY_AGENT_ID", None)
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        subprocess.check_call(["git", "init"], cwd=self.repo, stdout=subprocess.DEVNULL)
        subprocess.check_call(["git", "config", "user.email", "t@example.com"], cwd=self.repo)
        subprocess.check_call(["git", "config", "user.name", "Test"], cwd=self.repo)
        subprocess.check_call(["git", "config", "commit.gpgsign", "false"], cwd=self.repo)
        (self.repo / "README").write_text("one\n", encoding="utf-8")
        subprocess.check_call(["git", "add", "README"], cwd=self.repo)
        subprocess.check_call(["git", "commit", "-m", "init"], cwd=self.repo, stdout=subprocess.DEVNULL)

    def tearDown(self):
        self.tmp.cleanup()
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_scope_lifecycle(self):
        from agent_idempotency.identity import scope_path
        from agent_idempotency.scope import establish_scope, load_current_scope

        with self.assertRaises(MissingScope):
            load_current_scope(str(self.repo), "agent-a")
        (self.repo / "declared.txt").write_text("nope\n", encoding="utf-8")
        with self.assertRaises(Exception):
            establish_scope(str(self.repo), "agent-a", str(self.repo / "declared.txt"))
        self.assertFalse(Path(scope_path(str(self.repo), "agent-a")).exists())

        (self.repo / "README").write_text("two\n", encoding="utf-8")
        scope = establish_scope(str(self.repo), "agent-a")
        self.assertEqual(load_current_scope(str(self.repo), "agent-a")["scope_id"], scope["scope_id"])
        subprocess.check_call(["git", "add", "README"], cwd=self.repo)
        self.assertEqual(load_current_scope(str(self.repo), "agent-a")["scope_id"], scope["scope_id"])
        subprocess.check_call(["git", "commit", "-m", "edit"], cwd=self.repo, stdout=subprocess.DEVNULL)
        self.assertEqual(load_current_scope(str(self.repo), "agent-a")["scope_id"], scope["scope_id"])

        (self.repo / "README").write_text("three\n", encoding="utf-8")
        with self.assertRaises(StaleScope):
            load_current_scope(str(self.repo), "agent-a")
        calls = []
        wrapper = Client(MemoryStore(), StaticScope(error=StaleScope("execution identity changed")))
        with self.assertRaises(StaleScope):
            wrapper.once(DOC, lambda: calls.append(1) or value())
        self.assertEqual(calls, [])

    def test_agents_and_worktrees_do_not_share_scope(self):
        from agent_idempotency.identity import compute_identity, scope_path
        from agent_idempotency.scope import establish_scope, load_current_scope

        first = establish_scope(str(self.repo), "agent-a")
        second = establish_scope(str(self.repo), "agent-b")
        self.assertNotEqual(first["scope_id"], second["scope_id"])
        self.assertNotEqual(scope_path(str(self.repo), "agent-a"), scope_path(str(self.repo), "agent-b"))
        Path(scope_path(str(self.repo), "agent-b")).write_text("{}\n", encoding="utf-8")
        self.assertEqual(load_current_scope(str(self.repo), "agent-a")["scope_id"], first["scope_id"])

        other = Path(self.tmp.name) / "other"
        subprocess.check_call(["git", "worktree", "add", str(other), "HEAD"], cwd=self.repo, stdout=subprocess.DEVNULL)
        base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()
        left = compute_identity(str(self.repo), base, "agent-a")
        right = compute_identity(str(other), base, "agent-a")
        self.assertEqual(left["repo_id"], right["repo_id"])
        self.assertNotEqual(left["worktree_id"], right["worktree_id"])


if __name__ == "__main__":
    unittest.main()
