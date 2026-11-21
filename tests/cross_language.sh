#!/bin/bash
# Python writes a Redis record and Rust replays it, then the other way around.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TMP="$(mktemp -d)"
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
redis-server --port "$PORT" --bind 127.0.0.1 --save "" --appendonly no --dir "$TMP" --daemonize no >/dev/null 2>&1 &
REDIS_PID=$!
cleanup() {
  kill "$REDIS_PID" >/dev/null 2>&1 || true
  wait "$REDIS_PID" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

URL="redis://127.0.0.1:${PORT}/0"
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if redis-cli -p "$PORT" ping >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
redis-cli -p "$PORT" ping >/dev/null

export IDEMPOTENCY_TEST_REDIS_URL="$URL"
python3 - <<'PY'
import os
from agent_idempotency.client import Client
from agent_idempotency.store import RedisStore

class Scope:
    def current(self):
        return {"scope_id": "33" * 32}

client = Client(RedisStore(os.environ["IDEMPOTENCY_TEST_REDIS_URL"]), Scope(), record_ttl_seconds=120)
document = {"kind": "op", "name": "from-python"}
calls = []
result = client.once(document, lambda: calls.append(1) or {"kind": "value", "value": "from-python"})
assert result["value"] == "from-python", result
assert calls == [1]
PY

(cd "$ROOT/rust" && cargo test --locked --test cross_replay -- --nocapture)

python3 - <<'PY'
import os
from agent_idempotency.client import Client
from agent_idempotency.store import RedisStore

class Scope:
    def current(self):
        return {"scope_id": "33" * 32}

client = Client(RedisStore(os.environ["IDEMPOTENCY_TEST_REDIS_URL"]), Scope(), record_ttl_seconds=120)
document = {"kind": "op", "name": "from-rust"}
calls = []
result = client.once(document, lambda: calls.append(1) or {"kind": "value", "value": "no"})
assert result["value"] == "from-rust", result
assert calls == [], calls
PY

echo "cross-language replay ok"
