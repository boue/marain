"""Worktree execution identity. One implementation is shared by both SDKs and the hooks."""

import os
import stat
import subprocess
from typing import Any

from agent_idempotency.canonical import canonical_dumps, sha256_hex
from agent_idempotency.errors import IdentityError, MissingScope


def find_repo(start: str | None = None) -> str:
    proc = subprocess.run(
        ["git", "-C", start or os.getcwd(), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise IdentityError(proc.stderr.strip() or "not a git repository")
    return proc.stdout.strip()


def resolve_agent(repo: str, env: dict | None = None) -> str | None:
    env = os.environ if env is None else env
    chosen = env.get("IDEMPOTENCY_AGENT_ID", "").strip()
    if chosen:
        return chosen
    path = os.path.join(repo, ".idempotency", "agent-id")
    if not os.path.isfile(path):
        return None
    value = open(path, encoding="utf-8").read().strip()
    return value or None


def scope_path(repo: str, agent: str, env: dict | None = None) -> str:
    env = os.environ if env is None else env
    override = env.get("IDEMPOTENCY_SCOPE_FILE", "").strip()
    if override:
        return override if os.path.isabs(override) else os.path.join(repo, override)
    import re

    name = agent if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", agent) else sha256_hex(agent.encode("utf-8"))
    return os.path.join(repo, ".idempotency", "scopes", f"{name}.json")


def compute_identity(repo: str, base: str, agent: str) -> dict[str, str]:
    """Hash the worktree against `base`. The diff view is not an input."""
    text = fingerprint_text(repo, base)
    common = _git_text(repo, "rev-parse", "--git-common-dir").strip()
    common_abs = common if os.path.isabs(common) else os.path.join(repo, common)
    common_abs = os.path.realpath(common_abs)
    roots = sorted(line for line in _git_text(repo, "rev-list", "--max-parents=0", "HEAD").splitlines() if line)
    origin = _git_optional(repo, "remote", "get-url", "origin")
    repo_material = common_abs + "\n" + "\n".join(roots) + "\n" + origin
    top = os.path.realpath(_git_text(repo, "rev-parse", "--show-toplevel").strip())
    execution_id = sha256_hex(text.encode("utf-8"))
    repo_id = sha256_hex(repo_material.encode("utf-8"))
    worktree_id = sha256_hex(top.encode("utf-8"))
    return {
        "agent_id": agent,
        "base_head": base,
        "execution_id": execution_id,
        "repo_id": repo_id,
        "text": text,
        "worktree_id": worktree_id,
    }


def fingerprint_text(repo: str, base: str) -> str:
    entries: dict[str, str] = {}
    diff = _git_bytes(repo, "diff", "--name-status", "--no-renames", "-z", base)
    for status, path in _parse_name_status(diff):
        if _excluded(path):
            continue
        entries[path] = _entry_line(repo, path, deleted=status.startswith("D"))
    others = _git_bytes(repo, "ls-files", "--others", "--exclude-standard", "-z")
    for raw in others.split(b"\0"):
        if not raw:
            continue
        path = raw.decode("utf-8", "surrogateescape")
        if _excluded(path):
            continue
        entries[path] = _entry_line(repo, path, deleted=False)
    lines = [entries[path] for path in sorted(entries)]
    return "".join(f"{line}\n" for line in lines)


def staged_fingerprint(repo: str) -> str:
    """Index view. Stored as a hook note and never used as the execution id."""
    diff = _git_bytes(repo, "diff", "--cached", "--name-status", "--no-renames", "-z", "HEAD")
    lines = []
    for status, path in _parse_name_status(diff):
        if status.startswith("D"):
            lines.append(f"{path}\t000000\t-")
            continue
        blob = _git_text(repo, "rev-parse", f":{path}").strip()
        lines.append(f"{path}\tindex\t{blob}")
    lines.sort()
    return sha256_hex("".join(f"{line}\n" for line in lines).encode("utf-8"))


def scope_id_for(identity: dict[str, str]) -> str:
    document = {
        "agent_id": identity["agent_id"],
        "execution_id": identity["execution_id"],
        "repo_id": identity["repo_id"],
        "worktree_id": identity["worktree_id"],
    }
    return sha256_hex(canonical_dumps(document).encode("utf-8"))


def read_scope(path: str) -> dict[str, Any]:
    import json

    with open(path, encoding="utf-8") as handle:
        payload = json.loads(handle.read())
    if not isinstance(payload, dict):
        raise IdentityError("scope file is not an object")
    return payload


def write_scope(path: str, scope: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = f"{path}.tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        handle.write(canonical_dumps(scope) + "\n")
    os.replace(temporary, path)


def _entry_line(repo: str, path: str, *, deleted: bool) -> str:
    if deleted:
        return f"{path}\t000000\t-"
    full = os.path.join(repo, path)
    if not os.path.lexists(full):
        raise IdentityError(f"missing worktree path {path}")
    mode = os.lstat(full).st_mode
    if stat.S_ISLNK(mode):
        content = os.readlink(full).encode("utf-8", "surrogateescape")
        file_mode = "120000"
    elif stat.S_ISREG(mode):
        file_mode = "100755" if mode & stat.S_IXUSR else "100644"
        with open(full, "rb") as handle:
            content = handle.read()
    else:
        raise IdentityError(f"unsupported worktree path {path}")
    return f"{path}\t{file_mode}\t{sha256_hex(content)}"


def _excluded(path: str) -> bool:
    return path == ".idempotency" or path.startswith(".idempotency/")


def _parse_name_status(blob: bytes) -> list[tuple[str, str]]:
    parts = blob.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    items: list[tuple[str, str]] = []
    index = 0
    while index < len(parts):
        status = parts[index].decode("utf-8", "surrogateescape")
        index += 1
        if not parts or index >= len(parts):
            raise IdentityError("truncated git name-status output")
        if len(status) > 1 and status[0] in {"R", "C"}:
            if index + 1 >= len(parts):
                raise IdentityError("truncated git rename output")
            old = parts[index].decode("utf-8", "surrogateescape")
            new = parts[index + 1].decode("utf-8", "surrogateescape")
            index += 2
            items.append(("D", old))
            items.append(("A", new))
            continue
        path = parts[index].decode("utf-8", "surrogateescape")
        index += 1
        items.append((status, path))
    return items


def _git_bytes(repo: str, *args: str) -> bytes:
    proc = subprocess.run(["git", "-C", repo, "-c", "core.quotepath=false", *args], capture_output=True)
    if proc.returncode != 0:
        raise IdentityError(proc.stderr.decode("utf-8", "replace").strip() or "git failed")
    return proc.stdout


def _git_text(repo: str, *args: str) -> str:
    return _git_bytes(repo, *args).decode("utf-8", "surrogateescape")


def _git_optional(repo: str, *args: str) -> str:
    proc = subprocess.run(["git", "-C", repo, *args], capture_output=True)
    if proc.returncode != 0:
        return ""
    return proc.stdout.decode("utf-8", "replace").strip()


def require_agent(repo: str, env: dict | None = None) -> str:
    agent = resolve_agent(repo, env)
    if not agent:
        raise MissingScope("agent id is not set")
    return agent
