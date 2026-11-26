"""Visible record of calls that skipped the wrapper, and claims audit log."""

import os
import sys
import time

from agent_idempotency.canonical import canonical_dumps
from agent_idempotency.identity import find_repo


def call_unprotected(name: str, fn, *, detail: str = "", root: str | None = None):
    """Run `fn` with no idempotency key and append a bypass line."""
    directory = os.path.join(_root(root), ".idempotency")
    os.makedirs(directory, exist_ok=True)
    record = {
        "agent_id": os.environ.get("IDEMPOTENCY_AGENT_ID", ""),
        "detail": detail,
        "name": name,
        "protected": False,
    }
    with open(os.path.join(directory, "bypasses.jsonl"), "a", encoding="utf-8") as handle:
        handle.write(canonical_dumps(record) + "\n")
    return fn()


def write_claim(
    *,
    agent_id: str,
    scope_id: str,
    operation_id: str,
    outcome: str,
    repo_wide: bool = False,
    root: str | None = None,
) -> None:
    """Append a claim audit line. Fail-open: warn on error, never block."""
    directory = os.path.join(_root(root), ".idempotency")
    os.makedirs(directory, exist_ok=True)
    record = {
        "v": 1,
        "ts": int(time.time()),
        "agent_id": agent_id,
        "scope_id": scope_id,
        "operation_id": operation_id,
        "outcome": outcome,
        "repo_wide": repo_wide,
    }
    try:
        with open(os.path.join(directory, "claims.jsonl"), "a", encoding="utf-8") as handle:
            handle.write(canonical_dumps(record) + "\n")
    except Exception as exc:
        print(f"agent-idempotency: claims log write failed: {exc}", file=sys.stderr)


def bypass_log(root: str | None = None) -> str:
    return os.path.join(_root(root), ".idempotency", "bypasses.jsonl")


def claims_log(root: str | None = None) -> str:
    return os.path.join(_root(root), ".idempotency", "claims.jsonl")


def _root(root: str | None) -> str:
    if root:
        return root
    try:
        return find_repo()
    except Exception:
        return os.getcwd()
