"""Scope file channel. The wrapper never mints a scope."""

import os
import time

from agent_idempotency.errors import IdentityError, MissingScope, StaleScope
from agent_idempotency.identity import (
    compute_identity,
    find_repo,
    read_scope,
    require_agent,
    scope_id_for,
    scope_path,
    staged_fingerprint,
    write_scope,
)


class GitScope:
    """Reads the scope file for this agent and checks it against the worktree."""

    def __init__(self, repo: str | None = None, agent: str | None = None):
        self.repo = repo
        self.agent = agent

    def current(self) -> dict:
        repo = self.repo or find_repo()
        return load_current_scope(repo, self.agent)


def load_current_scope(repo: str, agent: str | None = None, env: dict | None = None) -> dict:
    agent = agent or require_agent(repo, env)
    path = scope_path(repo, agent, env)
    if not os.path.isfile(path):
        raise MissingScope("scope file is absent")
    scope = read_scope(path)
    if scope.get("agent_id") != agent:
        raise StaleScope("scope belongs to another agent")
    if scope.get("stale"):
        raise StaleScope(str(scope.get("stale_reason") or "scope is marked stale"))
    try:
        current = compute_identity(repo, str(scope["base_head"]), agent)
    except (IdentityError, KeyError) as exc:
        raise StaleScope("scope base is no longer usable") from exc
    if (
        current["repo_id"] != scope.get("repo_id")
        or current["worktree_id"] != scope.get("worktree_id")
        or current["execution_id"] != scope.get("execution_id")
    ):
        raise StaleScope("execution identity changed")
    return scope


def establish_scope(repo: str, agent: str, declared: str | None = None) -> dict:
    """Write this agent's scope file. A mismatched declaration writes nothing."""
    if not agent:
        raise MissingScope("agent id is not set")
    base = _head(repo)
    current = compute_identity(repo, base, agent)
    if declared is not None:
        with open(declared, encoding="utf-8") as handle:
            declared_text = handle.read()
        if declared_text != current["text"]:
            raise IdentityError("agent-declared diff does not match the worktree fingerprint")
    scope = {
        "agent_id": agent,
        "base_head": base,
        "established_at_unix": int(time.time()),
        "execution_id": current["execution_id"],
        "hook_notes": {},
        "repo_id": current["repo_id"],
        "scope_id": scope_id_for(current),
        "stale": False,
        "stale_reason": None,
        "v": 1,
        "worktree_id": current["worktree_id"],
    }
    write_scope(scope_path(repo, agent), scope)
    return scope


def update_notes(repo: str, agent: str, **notes) -> None:
    path = scope_path(repo, agent)
    scope = read_scope(path)
    hook_notes = scope.get("hook_notes") or {}
    if not isinstance(hook_notes, dict):
        hook_notes = {}
    hook_notes.update(notes)
    scope["hook_notes"] = hook_notes
    write_scope(path, scope)


def mark_post_commit(repo: str, agent: str) -> None:
    path = scope_path(repo, agent)
    scope = read_scope(path)
    try:
        current = compute_identity(repo, str(scope["base_head"]), agent)
    except (IdentityError, KeyError) as exc:
        scope["stale"] = True
        scope["stale_reason"] = str(exc) or "execution identity changed"
        write_scope(path, scope)
        return
    if (
        current["execution_id"] != scope.get("execution_id")
        or current["repo_id"] != scope.get("repo_id")
        or current["worktree_id"] != scope.get("worktree_id")
    ):
        scope["stale"] = True
        scope["stale_reason"] = "execution identity changed"
    else:
        notes = scope.get("hook_notes") or {}
        if not isinstance(notes, dict):
            notes = {}
        notes["last_head"] = _head(repo)
        scope["hook_notes"] = notes
    write_scope(path, scope)


def note_pre_commit(repo: str, agent: str) -> None:
    update_notes(repo, agent, pre_commit_staged=staged_fingerprint(repo))


def _head(repo: str) -> str:
    from agent_idempotency.identity import _git_text

    return _git_text(repo, "rev-parse", "HEAD").strip()
