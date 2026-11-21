"""Visible record of calls that skipped the wrapper."""

import os

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


def bypass_log(root: str | None = None) -> str:
    return os.path.join(_root(root), ".idempotency", "bypasses.jsonl")


def _root(root: str | None) -> str:
    if root:
        return root
    try:
        return find_repo()
    except Exception:
        return os.getcwd()
