# Idempotency protocol

Shared contract for the Python SDK, the Rust SDK, and the git hooks. A repeated execution suppresses a second side effect only when all of the following are true:

- The call goes through an enforcement boundary named below.
- A scope file for this agent and this worktree exists and is current for the execution identity.
- The canonical Redis key still holds a completed record inside the retention boundary.
- That record's result is replayable under the serialization contract.

Every other case has the outcome written in this document. A changed fingerprint, a missing or stale scope, an expired record, or a bypassed call is not a successful replay.

## Enforcement

Forced through the wrapper when the agent uses them:

- Python `Client.once`
- Python `http_request` and, after `install_urllib_enforcement`, `urllib.request.urlopen`
- Python `db_execute`
- Rust `Client::once`, `http::request`, and `db::execute`

Outside the guarantee, and visible only when the caller records it:

- Python `call_unprotected` appends a line to `.idempotency/bypasses.jsonl` and runs the call with no Redis key.
- Rust `audit::call_unprotected` does the same.
- `requests`, `httpx`, raw sockets, and database drivers used directly are not intercepted. They are unprotected even if no bypass line exists, because the process cannot see them.

`install_urllib_enforcement` is the HTTP interception mechanism. Database calls are not monkeypatched: a single `execute` does not reveal the transaction boundary, so only `db_execute` is inside the guarantee. A bypassed call is the acceptance case that performs the side effect on every invocation and writes a bypass line.

## Scope handoff

Hooks do not export environment variables into the parent agent. The agent reads `.idempotency/scopes/<agent-id>.json`. `IDEMPOTENCY_SCOPE_FILE` overrides that path. A bare scope id in the environment is not a scope.

The agent id is `IDEMPOTENCY_AGENT_ID`, otherwise the gitignored file `.idempotency/agent-id`. The installer may create that file once. It does not create a scope. Two processes that need isolation set different agent ids. Processes that share an agent id are the same agent and the same scope.

- No establish has run. The wrapper raises `missing_scope` and does not claim, replay, or call out.
- The scope file is stale for this agent, worktree, or execution identity. The wrapper raises `stale_scope` and does not claim, replay, or call out. A stored Redis result is not returned.
- Concurrent agents use different scope files. Concurrent worktrees hash different worktree paths. One agent does not read, refresh, or resolve another agent's file.

Scope is created only by `agent-idempotency establish`, which the agent runs before side effects. `pre-commit` may record the staged-diff fingerprint under `hook_notes`. It does not create or rotate a scope. `note` and active hook processing may update `hook_notes` or `stale` on an existing scope file. They do not create a scope.

## Execution identity

`repo_id` is SHA-256 over the absolute git common directory, the sorted root commit ids, and the `origin` URL (empty if there is no origin).

`worktree_id` is SHA-256 over the absolute worktree root.

`execution_id` is SHA-256 over sorted lines `path<TAB>mode<TAB>contentsha` for the worktree compared with `base_head` (the HEAD recorded at establish):

- Included: tracked additions, modifications, and deletions versus `base_head` (`git diff --no-renames`), plus untracked files that are not gitignored. Mode is `100644`, `100755`, `120000`, or `000000` for a deletion. Content is SHA-256 of the worktree bytes, or of the symlink target. `.idempotency/**` is excluded.
- Excluded: the staged-versus-unstaged view, the post-commit move of HEAD, gitignored files, and the agent-declared diff.

The identity always uses worktree bytes versus the original `base_head`. Staging the same bytes, or committing them, does not change the fingerprint. A later edit does.

An agent-declared diff is a confirmation. If it is supplied and differs, establish writes nothing and fails. The declaration is not an input to the hash.

A new fingerprint does not open a scope by itself. The current scope becomes stale, and calls fail closed until establish is run again. That command is the only rule that mints a new execution identity.

`scope_id` is SHA-256 of the canonical JSON object whose keys are `agent_id`, `execution_id`, `repo_id`, and `worktree_id`.

## Canonicalization

Both SDKs implement this text. Token tests use `protocol/fixtures/tokens.json`.

Canonical JSON:

- UTF-8, no insignificant whitespace, objects sorted by key code point.
- Strings use JSON short escapes `\" \\ \b \f \n \r \t` and `\u00xx` for other controls. Non-ASCII is raw UTF-8. `/` is not escaped.
- Integers in the closed range from `-2^63` to `2^63-1`. Floats, exponents, `NaN`, and integers outside that range are rejected.
- No Unicode normalization. Duplicate JSON object keys keep the last value.

Token:

```text
operation_id = hex(sha256(canonical_json(operation)))
token = hex(sha256(utf8(scope_id + "\n" + operation_id)))
redis key = "idempotency:v1:" + token
```

HTTP operation document:

- `kind` is `http`.
- Method is uppercased.
- URL scheme and host are lowercased. Userinfo and the fragment are dropped. Default ports 80 and 443 are dropped. The path is decoded, `.` and `..` are resolved, the path is never empty, and bytes other than unreserved characters are uppercase percent-encoding. The query is split on `&`, decoded, re-encoded with `%20` for space, and sorted by key then value.
- Headers in the identity are only `accept` and `content-type`, names lowercased, values trimmed. `authorization`, `cookie`, `date`, `host`, `user-agent`, and every other header are volatile and are not part of the token. Two calls that differ only by those headers share a token.
- A JSON content type (`application/json` or `+json`) with a UTF-8 object or array body is canonical JSON. Any other body, including invalid JSON, is lowercase hex of the raw bytes. An empty body is `{"kind":"empty"}`.

Database operation document:

- `kind` is `db`.
- `target` is `driver`, `host`, `port`, `database`, and `user`. A password field is rejected before a claim. There is no caller-chosen operation name, so identical target, transaction, and statements share one token.
- `transaction.boundary` is `single_transaction`. `transaction.isolation` is the isolation the wrapper opens.
- `statements` are the exact SQL strings, unparsed, in order, with typed parameters `null`, `bool`, `int`, `string`, `bytes` (base64), or `json`.

Hook operation document: `{"kind":"hook","hook":"<name>"}`.

## Serialization

The stored success body is one of:

- `{"kind":"value","value":<canonical json>}`
- `{"kind":"http_response","status":<int>,"headers":[[name,value],...],"body_base64":"..."}`
- `{"kind":"db_result","committed":true,"rows_affected":[int,...],"rows":[[typed,...],...]}`

A completed error outcome is `{"outcome":"error","body":{"code":"...","message":"..."}}`. Replay raises that code and does not call out. A success outcome is `{"outcome":"success","body":<contract>}`.

Not replayable, and not stored as a completed success:

- Streaming bodies. The HTTP wrapper buffers the full body. It does not accept a stream.
- A result whose canonical envelope exceeds `IDEMPOTENCY_MAX_RESULT_BYTES` (default 65536). The record becomes `blocked` with reason `oversized_result`. The callback has already run. A later call does not run it.
- A value outside the contract (`nonserializable_result`), same blocking behavior.
- Binary HTTP bodies are base64 inside `http_response` and are subject to the same size limit.

Oversized recovery: a caller that still holds the current scope may `resolve_blocked` with decision `complete`, non-empty evidence, and a contract value that fits. Later calls replay that summary. Decision `release` deletes the key only when the caller supplies evidence; the next claim may dispatch again. Release does not retain the evidence in Redis.

## Redis record

Key prefix `idempotency:v1:`. The value is a JSON object: `state`, `dispatched`, `scope_id`, `operation_id`, `owner`, `fence`, `lock_expires_at_ms`, `snapshot`, `result`, `reason`. `snapshot` and `result` are canonical JSON text. Redis cjson would otherwise store an empty array as an object. A reader accepts that text, and also an object written by an older record.

States are `empty` (no key), `in_progress`, `completed`, and `blocked`.

Atomic operations live in `protocol/redis/record.lua`: `claim`, `mark_dispatched`, `complete`, `abort`, `release_not_applied`, `block`, `read`, `resolve`.

- Claim writes `in_progress` only when the key is absent. It increments a fencing counter on `idempotency:v1:fence:<token>` and stores that fence with a new owner id.
- `mark_dispatched` requires the same owner and fence, `in_progress`, and a live lock.
- `complete` requires those plus `dispatched` and a live lock.
- `abort` deletes the key only when this owner has not marked dispatched.
- `release_not_applied` deletes the key when this owner has marked dispatched and attests the external system did not apply the call, and the lock is still live.
- A stale owner or stale fence is `stale_owner`. The record is not modified.
- An in-progress record whose lock time has passed becomes `blocked` with reason `lock_expired` on the next atomic read or mutation. It does not become empty. A late complete from the old owner does not write a success, including when a newer owner holds the key after a later claim.
- Waiters poll `read` until `IDEMPOTENCY_WAIT_MS` (default 120000), every `IDEMPOTENCY_POLL_MS` (default 100). They never call out. After the bound they read once more: completed replays, blocked stays blocked, `in_progress` raises `waiter_timeout`, and a missing key raises `in_progress_cleared`.
- If Redis cannot be claimed, or the claim result is corrupt, the wrapper raises `redis_unavailable` and does not call out.

Lock TTL defaults to 120000 ms (`IDEMPOTENCY_LOCK_TTL_MS`). It is a timestamp inside the record, compared with Redis `TIME`. It is not extended at dispatch. A call that outlives the lock finds the record blocked and cannot complete it.

## Retention

`IDEMPOTENCY_RECORD_TTL_SECONDS` is the retention boundary. The default is 86400 seconds. It is set when the key is claimed and is not refreshed by later transitions. The fence key uses the same TTL.

The repeated-execution guarantee for a key lasts only while that key exists. When a completed record or a blocked record expires, the next call observes an empty key, claims it, and may dispatch again. Expiry is not a distinct error. It is the end of the guarantee for that key. The 24-hour default is this configured boundary, not an unbounded promise.

The same TTL is the exposure window for whatever the record still holds.

## Side effects

`dispatched` means the wrapper decided to invoke the callback. It does not mean the external system applied the effect. Only a completed success outcome is an applied effect that replays as success.

Handled failure before `mark_dispatched` aborts the key. One later call may claim and dispatch. A crash after the claim and before the mark does not abort. The lock then expires into `blocked`, and a retry does not dispatch until resolve.

After the mark:

- A known HTTP response, including 4xx and 5xx, is completed and replayed. The outcome is known because the response bytes were received.
- Timeout, connection reset, or an incomplete read is `uncertain_http_outcome`. The record is blocked. A retry does not send again.
- DNS failure, connection refused, or a TLS failure before any request byte is written is `release_not_applied`. One later call may dispatch.
- Any other callback exception is `uncertain_exception` and blocks.

Database boundary is one transaction around the whole statement list:

- The session must not already be in a transaction. Otherwise the wrapper raises `transaction_boundary` and does not claim.
- `BEGIN` failure releases the key (nothing was opened).
- A statement failure followed by a confirmed rollback is stored as completed error `rolled_back`. Replay raises `rolled_back` and does not execute. It is not a successful commit, and a partial list is not replayed as one.
- A failed rollback, or a commit whose result is unknown, blocks as `uncertain_database`. A retry does not execute.
- A confirmed commit stores `db_result` with `committed: true`.

Blocked reconciliation is `resolve_blocked`. The caller must present the same current scope and non-empty evidence. `release` deletes the key. `complete` stores a contract result that fits the size limit. No automatic resolver runs.

## Fingerprint command

`agent-idempotency fingerprint --repo <path> --base <head>` writes one canonical JSON object and a newline on stdout. The keys are `base_head`, `execution_id`, `repo_id`, and `worktree_id`. No other bytes are written to stdout.

On failure the process exits 1. Stdout is empty. Stderr carries the `idempotency:` message. A missing command, a non-zero status, or non-JSON stdout is a stale scope for the Rust reader. The reader does not call out.

The Python command and the Rust crate are a pair from the same commit of this repository. Another revision on `PATH` is unsupported.

## Hooks

`agent-idempotency install-hooks` writes into the current `core.hooksPath` when it is set, otherwise into `git rev-parse --git-path hooks`. It does not change `core.hooksPath`. An existing hook is copied to `<name>.idempotency-preserved` only when that preserved file is absent and the live hook is not already a chain stub. An existing preserved file is kept. The live hook becomes a stub that execs `agent-idempotency run-hook`. A second install does not wrap the stub again.

When `agent-idempotency` is absent from `PATH`, passive mode warns and still runs the preserved command. Active mode exits 127 and does not run the preserved command.

`run-hook` modes come from `IDEMPOTENCY_HOOK_MODE` (`passive` by default).

Passive:

- Does not contact Redis.
- Does not create a scope.
- Records hook notes when a current scope exists.
- Runs the preserved command. A missing scope prints a warning and still runs that command. A failed note warns and still runs that command.

Active, for `pre-commit` and `post-commit`:

- Wrapped command: the preserved hook, if one exists.
- Claim: the hook operation under the current scope.
- Missing scope, stale scope, or Redis failure on `pre-commit`: exit non-zero and do not run the preserved command.
- `post-commit` with a missing scope: the commit already exists, so the hook logs and exits 0. It does not create a scope.
- Completed record whose stored exit code is 0, while the scope is still current: skip the preserved command and exit 0. This skip is safe only in that case.
- Non-zero preserved exit: release the key and propagate the status, so a failed check runs again on the next attempt.
- Preserved command killed by a signal: block, and exit non-zero. The next attempt does not run it until resolve.
- `pre-commit` additionally stores the staged fingerprint in `hook_notes`. That note is not the execution id.
- `post-commit` marks the scope stale when the worktree no longer matches `base_head`, otherwise records the new HEAD in `hook_notes`.

## Security

Anyone who can authenticate to Redis and read this prefix can read records. The SDK does not add an ACL. Operators should limit the Redis user to the prefix `idempotency:v1:*` and to `GET`, `SET`, `DEL`, `EVAL`, `TIME`, `EXPIRE`, and `INCR`.

`IDEMPOTENCY_REQUIRE_TLS=1` refuses a URL that does not start with `rediss://` and does not call out. The default allows `redis://` for a local server. Production should set the flag.

The operation snapshot stored on the record has values redacted when the key matches `password`, `secret`, `token`, `authorization`, `api_key`, `api-key`, or `credential` (case insensitive). SQL text is not parsed, so literals in SQL remain. The token is computed from the unredacted canonical operation, so two different secrets do not share a key unless they were excluded as volatile headers.

Results are not redacted. Replay would otherwise lie. When `IDEMPOTENCY_RECORD_KEY` is 32 bytes encoded as 64 hex characters, the snapshot and the result are encrypted with AES-256-GCM before they are written. The nonce is random. The associated data is the token. Without that key, Redis stores the result as JSON for the retention window. That window is the exposure bound.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `IDEMPOTENCY_REDIS_URL` | unset | Redis connection. Required to claim. |
| `IDEMPOTENCY_RECORD_TTL_SECONDS` | `86400` | Retention boundary. |
| `IDEMPOTENCY_LOCK_TTL_MS` | `120000` | In-progress lock. |
| `IDEMPOTENCY_WAIT_MS` | `120000` | Waiter bound. |
| `IDEMPOTENCY_POLL_MS` | `100` | Waiter poll. |
| `IDEMPOTENCY_MAX_RESULT_BYTES` | `65536` | Contract envelope limit. |
| `IDEMPOTENCY_RECORD_KEY` | unset | 64 hex characters, optional AES-256-GCM. |
| `IDEMPOTENCY_REQUIRE_TLS` | unset | `1` requires `rediss://`. |
| `IDEMPOTENCY_AGENT_ID` | `.idempotency/agent-id` | Agent identity. |
| `IDEMPOTENCY_SCOPE_FILE` | `.idempotency/scopes/<agent>.json` | Scope channel. |
| `IDEMPOTENCY_HOOK_MODE` | `passive` | `active` claims a hook key. |

## Acceptance

Each case names the observation that makes it pass:

- Same HTTP call in one current scope: one transport invocation, the second returns the stored response.
- Same database transaction in one current scope: one execution, the second returns the stored result.
- Two overlapping callers: one callback invocation.
- Lock expiry after dispatch: the record is blocked and the retry does not call out.
- Handled failure before dispatch: the key is cleared and exactly one later call runs the callback.
- Python and Rust tokens match `protocol/fixtures/tokens.json`.
- Python writes a Redis record and Rust replays it. Rust writes a Redis record and Python replays it.
- The same patch fingerprint reuses the scope. Active mode skips a preserved hook whose stored exit code is 0.
- Missing scope, stale scope, and Redis outage do not call out.
- Record expiry of a completed record and of a blocked record allows a new dispatch.
- A stale owner cannot clear or complete a newer owner's record.
- An oversized result blocks, and resolve-complete with a fitting summary is what later calls replay.
- A nonserializable result blocks and does not replay as success.
- An HTTP timeout blocks as `uncertain_http_outcome`.
- A database rollback replays `rolled_back` and does not leave a committed row.
- `call_unprotected` runs the side effect twice and appends two bypass lines.
- Every claim writes a line to `.idempotency/claims.jsonl` with `agent_id`, `scope_id`, `operation_id`, `resource_key`, `outcome` (`sent`, `replayed`, or `blocked`), `ts`, and `repo_wide`.
- `resource_key` for HTTP is `method:host:path` with numeric segments replaced by `:id`.
- `resource_key` for DB is `driver:database:sorted_tables` extracted by regex from the main statement.
- `resource_key` for hooks is `hook:<name>`.
- `repo_wide: true` in the operation document uses `repo_id` instead of `scope_id` for the token.
- `agent-idempotency hotspots` groups claims by `resource_key`, counts distinct agents, and flags operations sent under more than one scope.
