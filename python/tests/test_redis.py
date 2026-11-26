"""Lua transitions against a private Redis server."""

import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest

from agent_idempotency.canonical import canonical_dumps, token_for
from agent_idempotency.client import Client
from agent_idempotency.db import SqliteSession, db_execute, statement
from agent_idempotency.errors import Blocked
from agent_idempotency.store import RedisStore

SCOPE_ID = "22" * 32
DOC = {"kind": "op", "name": "redis"}


class StaticScope:
    def current(self):
        return {"scope_id": SCOPE_ID}


def _port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class RedisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.port = _port()
        cls.proc = subprocess.Popen(
            [
                "redis-server",
                "--port",
                str(cls.port),
                "--bind",
                "127.0.0.1",
                "--save",
                "",
                "--appendonly",
                "no",
                "--dir",
                cls.tmp.name,
                "--dbfilename",
                "dump.rdb",
                "--daemonize",
                "no",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cls.url = f"redis://127.0.0.1:{cls.port}/0"
        deadline = time.time() + 5
        last = None
        while time.time() < deadline:
            try:
                RedisStore(cls.url).call("read", "health")
                return
            except Exception as exc:
                last = exc
                if cls.proc.poll() is not None:
                    break
                time.sleep(0.05)
        raise RuntimeError(f"redis did not start: {last}")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        cls.tmp.cleanup()

    def test_cross_process_claim_expiry_and_stale_owner(self):
        store = RedisStore(self.url)
        wrapper = Client(store, StaticScope(), record_ttl_seconds=30, lock_ttl_ms=400, wait_ms=2000, poll_ms=20)
        calls = []
        started = threading.Event()
        release = threading.Event()

        def run():
            calls.append(1)
            started.set()
            release.wait(3)
            return {"kind": "value", "value": "once"}

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

        slow = {"kind": "op", "name": "slow"}
        slow_calls = []

        def expire():
            slow_calls.append(1)
            time.sleep(0.5)
            return {"kind": "value", "value": "too-late"}

        with self.assertRaises(Blocked) as raised:
            wrapper.once(slow, expire)
        self.assertEqual(raised.exception.reason, "lock_expired")
        with self.assertRaises(Blocked):
            wrapper.once(slow, expire)
        self.assertEqual(slow_calls, [1])

        token = token_for(SCOPE_ID, __import__("agent_idempotency.canonical", fromlist=["operation_id"]).operation_id(DOC))
        record = store.peek(token)
        self.assertEqual(record["state"], "completed")
        store._redis.pexpire(__import__("agent_idempotency.canonical", fromlist=["redis_key"]).redis_key(token), 1)
        time.sleep(0.05)
        again = []
        wrapper.once(DOC, lambda: again.append(1) or {"kind": "value", "value": "fresh"})
        self.assertEqual(again, [1])

        blocked_doc = {"kind": "op", "name": "will-block"}
        with self.assertRaises(Blocked):
            wrapper.once(blocked_doc, lambda: (_ for _ in ()).throw(RuntimeError("unknown")))
        blocked_token = token_for(
            SCOPE_ID,
            __import__("agent_idempotency.canonical", fromlist=["operation_id"]).operation_id(blocked_doc),
        )
        self.assertEqual(store.peek(blocked_token)["state"], "blocked")
        store._redis.pexpire(__import__("agent_idempotency.canonical", fromlist=["redis_key"]).redis_key(blocked_token), 1)
        time.sleep(0.05)
        after = []
        wrapper.once(blocked_doc, lambda: after.append(1) or {"kind": "value", "value": "retried"})
        self.assertEqual(after, [1])

        claim_body = canonical_dumps({"operation_id": "op", "scope_id": "sc"})
        first = store.call("claim", "fence-tok", owner="owner-a", body=claim_body, lock_ttl_ms=50, record_ttl_seconds=30)
        time.sleep(0.08)
        self.assertEqual(store.call("read", "fence-tok")["status"], "blocked")
        released = store.call(
            "resolve",
            "fence-tok",
            body=canonical_dumps(
                {"decision": "release", "evidence": "checked the remote", "result_json": "", "scope_id": "sc"}
            ),
        )
        self.assertEqual(released["status"], "released")
        store.call("claim", "fence-tok", owner="owner-b", body=claim_body, lock_ttl_ms=5000, record_ttl_seconds=30)
        stale = store.call(
            "complete",
            "fence-tok",
            owner="owner-a",
            fence=first["record"]["fence"],
            body=canonical_dumps({"body": {"kind": "value", "value": "no"}, "outcome": "success"}),
            max_bytes=100000,
        )
        self.assertEqual(stale["status"], "stale_owner")
        self.assertEqual(store.peek("fence-tok")["owner"], "owner-b")
        self.assertIsNone(store.peek("missing-token"))

    def test_empty_sqlite_rows_replay_unchanged(self):
        connection = sqlite3.connect(":memory:")
        session = SqliteSession(connection)
        session.connection.execute("create table t (id integer primary key, n integer)")
        session.connection.commit()
        target = {"database": "app", "driver": "sqlite", "host": "", "port": 0, "user": "agent"}
        statements = [statement("insert into t (id, n) values (?, ?)", [1, 7])]
        wrapper = Client(RedisStore(self.url), StaticScope(), record_ttl_seconds=30)
        stored = db_execute(wrapper, target, statements, session)
        again = db_execute(wrapper, target, statements, session)
        self.assertEqual(stored["rows"], [[]])
        self.assertEqual(again, stored)
        self.assertEqual(connection.execute("select count(*) from t").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
