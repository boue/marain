#!/bin/bash
# Hook installer and dispatcher coverage.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP"
}
trap cleanup EXIT

init_repo() {
  local repo="$1"
  mkdir -p "$repo"
  git -C "$repo" init >/dev/null
  git -C "$repo" config user.email t@example.com
  git -C "$repo" config user.name Test
  git -C "$repo" config commit.gpgsign false
  echo one > "$repo/README"
  git -C "$repo" add README
  git -C "$repo" commit -m init >/dev/null
}

write_hook() {
  local path="$1"
  local log="$2"
  local code="${3:-0}"
  mkdir -p "$(dirname "$path")"
  cat > "$path" <<EOF
#!/bin/bash
echo "\$*" >> "$log"
echo RAN >> "$log"
pwd >> "$log"
exit $code
EOF
  chmod +x "$path"
}

start_redis() {
  PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
  redis-server --port "$PORT" --bind 127.0.0.1 --save "" --appendonly no --dir "$TMP" --daemonize no >/dev/null 2>&1 &
  REDIS_PID=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    redis-cli -p "$PORT" ping >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  return 1
}

REPO="$TMP/relative"
LOG="$TMP/relative.log"
init_repo "$REPO"
write_hook "$REPO/.githooks/pre-commit" "$LOG" 0
git -C "$REPO" config core.hooksPath .githooks
BEFORE="$(git -C "$REPO" config --get core.hooksPath)"
ORIGINAL="$(cat "$REPO/.githooks/pre-commit")"
(cd "$REPO" && agent-idempotency install-hooks >/dev/null)
(cd "$REPO" && agent-idempotency install-hooks >/dev/null)
AFTER="$(git -C "$REPO" config --get core.hooksPath)"
test "$BEFORE" = "$AFTER"
test "$AFTER" = ".githooks"
grep -q IDEMPOTENCY_HOOK_CHAIN "$REPO/.githooks/pre-commit"
test "$(cat "$REPO/.githooks/pre-commit.idempotency-preserved")" = "$ORIGINAL"
grep -c IDEMPOTENCY_HOOK_CHAIN "$REPO/.githooks/pre-commit" | grep -qx 1
test -x "$REPO/.githooks/pre-commit"

: > "$LOG"
(cd "$REPO" && .githooks/pre-commit >/tmp/marain-hook-err 2>&1 || true)
grep -q "no scope" /tmp/marain-hook-err
test "$(grep -c RAN "$LOG")" = "1"
test ! -e "$REPO/.idempotency/scopes"

mkdir -p "$REPO/nested"
: > "$LOG"
(cd "$REPO/nested" && "$REPO/.githooks/pre-commit" one two)
grep -qx "one two" "$LOG"
grep -qx "$REPO" "$LOG"

ARGS_LOG="$TMP/args.log"
write_hook "$REPO/.githooks/pre-commit.idempotency-preserved" "$ARGS_LOG" 3
: > "$ARGS_LOG"
set +e
(cd "$REPO" && .githooks/pre-commit alpha beta >/dev/null)
STATUS=$?
set -e
test "$STATUS" = "3"
grep -qx "alpha beta" "$ARGS_LOG"

start_redis
export IDEMPOTENCY_REDIS_URL="redis://127.0.0.1:${PORT}/0"
export IDEMPOTENCY_AGENT_ID="hook-agent"
export IDEMPOTENCY_HOOK_MODE="active"
: > "$LOG"
write_hook "$REPO/.githooks/pre-commit.idempotency-preserved" "$LOG" 0
set +e
(cd "$REPO" && .githooks/pre-commit >/tmp/marain-hook-active 2>&1)
STATUS=$?
set -e
test "$STATUS" -ne 0
test ! -s "$LOG"

POST_LOG="$TMP/post.log"
write_hook "$REPO/.githooks/post-commit" "$POST_LOG" 0
(cd "$REPO" && agent-idempotency install-hooks >/dev/null)
: > "$POST_LOG"
set +e
(cd "$REPO" && .githooks/post-commit >/tmp/marain-post-missing 2>&1)
STATUS=$?
set -e
test "$STATUS" = "0"
test ! -s "$POST_LOG"

unset IDEMPOTENCY_HOOK_MODE
FIRST="$(cd "$REPO" && agent-idempotency establish)"
SECOND="$(cd "$REPO" && agent-idempotency establish)"
test "$FIRST" = "$SECOND"
test -n "$FIRST"

export IDEMPOTENCY_HOOK_MODE="active"
: > "$LOG"
(cd "$REPO" && .githooks/pre-commit)
(cd "$REPO" && .githooks/pre-commit)
test "$(grep -c RAN "$LOG")" = "1"

: > "$POST_LOG"
(cd "$REPO" && .githooks/post-commit)
python3 - "$REPO" <<'PY'
import json, sys
path = sys.argv[1] + "/.idempotency/scopes/hook-agent.json"
scope = json.load(open(path))
assert scope["hook_notes"]["last_head"]
assert scope["stale"] is False
PY
test "$(grep -c RAN "$POST_LOG")" = "1"

echo more >> "$REPO/README"
set +e
(cd "$REPO" && agent-idempotency validate >/tmp/marain-stale 2>&1)
STATUS=$?
set -e
test "$STATUS" -eq 2

: > "$POST_LOG"
set +e
(cd "$REPO" && .githooks/post-commit >/tmp/marain-post-stale 2>&1)
STATUS=$?
set -e
test "$STATUS" = "0"
test ! -s "$POST_LOG"

unset IDEMPOTENCY_HOOK_MODE
printf 'not-json' > "$REPO/.idempotency/scopes/hook-agent.json"
: > "$LOG"
(cd "$REPO" && .githooks/pre-commit >/tmp/marain-note-fail 2>&1 || true)
grep -q "scope note failed" /tmp/marain-note-fail
test "$(grep -c RAN "$LOG")" = "1"

BARE="$TMP/bare"
init_repo "$BARE"
(cd "$BARE" && agent-idempotency install-hooks >/dev/null)
test -x "$BARE/.git/hooks/pre-commit"
test ! -e "$BARE/.git/hooks/pre-commit.idempotency-preserved"
(cd "$BARE" && .git/hooks/post-commit)

ABS="$TMP/absolute-hooks"
ABS_REPO="$TMP/absolute"
init_repo "$ABS_REPO"
mkdir -p "$ABS"
git -C "$ABS_REPO" config core.hooksPath "$ABS"
(cd "$ABS_REPO" && agent-idempotency install-hooks >/dev/null)
test -x "$ABS/pre-commit"
test "$(git -C "$ABS_REPO" config --get core.hooksPath)" = "$ABS"

COLLIDE="$TMP/collide"
COLLIDE_REPO="$TMP/collide-repo"
init_repo "$COLLIDE_REPO"
mkdir -p "$COLLIDE"
echo 'LIVE' > "$COLLIDE/pre-commit"
echo 'KEEP' > "$COLLIDE/pre-commit.idempotency-preserved"
chmod +x "$COLLIDE/pre-commit" "$COLLIDE/pre-commit.idempotency-preserved"
git -C "$COLLIDE_REPO" config core.hooksPath "$COLLIDE"
(cd "$COLLIDE_REPO" && agent-idempotency install-hooks >/dev/null)
test "$(cat "$COLLIDE/pre-commit.idempotency-preserved")" = "KEEP"
grep -q IDEMPOTENCY_HOOK_CHAIN "$COLLIDE/pre-commit"

MISS="$TMP/missing-cli"
init_repo "$MISS"
write_hook "$MISS/.githooks/pre-commit" "$TMP/missing.log" 0
git -C "$MISS" config core.hooksPath .githooks
(cd "$MISS" && agent-idempotency install-hooks >/dev/null)
: > "$TMP/missing.log"
env -u IDEMPOTENCY_HOOK_MODE PATH="/usr/bin:/bin" "$MISS/.githooks/pre-commit" >/tmp/marain-missing-passive 2>&1 || true
grep -q "not on PATH" /tmp/marain-missing-passive
test "$(grep -c RAN "$TMP/missing.log")" = "1"
: > "$TMP/missing.log"
set +e
env IDEMPOTENCY_HOOK_MODE=active PATH="/usr/bin:/bin" "$MISS/.githooks/pre-commit" >/tmp/marain-missing-active 2>&1
STATUS=$?
set -e
test "$STATUS" = "127"
test ! -s "$TMP/missing.log"

if [ -n "${REDIS_PID:-}" ]; then
  kill "$REDIS_PID" >/dev/null 2>&1 || true
  wait "$REDIS_PID" >/dev/null 2>&1 || true
fi

echo "hooks ok"
