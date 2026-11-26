"""Commands used by the git hooks. Passive mode never contacts Redis."""

import argparse
import os
import shlex
import shutil
import subprocess
import sys
import uuid

from agent_idempotency.client import Client
from agent_idempotency.errors import IdempotencyError, MissingScope, NotApplied, StaleScope, UncertainOutcome
from agent_idempotency.identity import _git_optional, find_repo, require_agent
from agent_idempotency.scope import establish_scope, load_current_scope, mark_post_commit, note_pre_commit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-idempotency")
    sub = parser.add_subparsers(dest="command", required=True)
    establish = sub.add_parser("establish")
    establish.add_argument("--declared", default="")
    fingerprint = sub.add_parser("fingerprint")
    fingerprint.add_argument("--base", default="")
    fingerprint.add_argument("--repo", default="")
    note = sub.add_parser("note")
    note.add_argument("--hook", required=True)
    active = sub.add_parser("active")
    active.add_argument("--hook", required=True)
    active.add_argument("--preserved", default="")
    active.add_argument("args", nargs=argparse.REMAINDER)
    sub.add_parser("validate")
    sub.add_parser("install-hooks")
    hotspots = sub.add_parser("hotspots")
    hotspots.add_argument("--since", default="7d")
    hotspots.add_argument("--agent", default="")
    hotspots.add_argument("--min-agents", type=int, default=2)
    hotspots.add_argument("--log", default="")
    run_hook = sub.add_parser("run-hook")
    run_hook.add_argument("hook")
    run_hook.add_argument("preserved", nargs="?", default="")
    run_hook.add_argument("args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.command == "establish":
        return _establish(args.declared or None)
    if args.command == "fingerprint":
        return _fingerprint(args.repo or None, args.base or None)
    if args.command == "note":
        return _note(args.hook)
    if args.command == "active":
        extra = list(args.args)
        if extra and extra[0] == "--":
            extra = extra[1:]
        return _active(args.hook, args.preserved, extra)
    if args.command == "validate":
        return _validate()
    if args.command == "install-hooks":
        return _install_hooks()
    if args.command == "hotspots":
        from agent_idempotency.hotspots import main as hotspots_main
        return hotspots_main([
            "--since", args.since,
            "--agent", args.agent,
            "--min-agents", str(args.min_agents),
            "--log", args.log,
        ])
    if args.command == "run-hook":
        extra = list(args.args)
        if extra and extra[0] == "--":
            extra = extra[1:]
        return _run_hook(args.hook, args.preserved, extra)
    return 2


def _at_repo() -> str:
    repo = find_repo()
    os.chdir(repo)
    return repo


def _establish(declared: str | None) -> int:
    repo = _at_repo()
    try:
        agent = require_agent(repo)
        scope = establish_scope(repo, agent, declared)
    except (IdempotencyError, OSError) as exc:
        print(f"idempotency: {exc}", file=sys.stderr)
        return 1
    print(scope["scope_id"])
    return 0


def _fingerprint(repo: str | None, base: str | None) -> int:
    from agent_idempotency.canonical import canonical_dumps
    from agent_idempotency.identity import _git_text, compute_identity

    repo = repo or find_repo()
    agent = os.environ.get("IDEMPOTENCY_AGENT_ID", "") or "fingerprint"
    base = base or _git_text(repo, "rev-parse", "HEAD").strip()
    try:
        current = compute_identity(repo, base, agent)
    except IdempotencyError as exc:
        print(f"idempotency: {exc}", file=sys.stderr)
        return 1
    print(
        canonical_dumps(
            {
                "base_head": current["base_head"],
                "execution_id": current["execution_id"],
                "repo_id": current["repo_id"],
                "worktree_id": current["worktree_id"],
            }
        )
    )
    return 0


def _note(hook: str) -> int:
    repo = _at_repo()
    try:
        agent = require_agent(repo)
        load_current_scope(repo, agent)
    except MissingScope:
        print("idempotency: no scope; calls are unprotected until establish", file=sys.stderr)
        return 0
    except StaleScope as exc:
        print(f"idempotency: stale scope: {exc}", file=sys.stderr)
        return 0
    if hook == "pre-commit":
        note_pre_commit(repo, agent)
    elif hook == "post-commit":
        mark_post_commit(repo, agent)
    return 0


def _validate() -> int:
    repo = _at_repo()
    try:
        scope = load_current_scope(repo, require_agent(repo))
    except (MissingScope, StaleScope) as exc:
        print(f"idempotency: {exc}", file=sys.stderr)
        return 2
    print(scope["scope_id"])
    return 0


def _active(hook: str, preserved: str, args: list[str]) -> int:
    repo = _at_repo()
    try:
        agent = require_agent(repo)
        load_current_scope(repo, agent)
    except MissingScope:
        print("idempotency: no current scope", file=sys.stderr)
        return 0 if hook == "post-commit" else 1
    except StaleScope as exc:
        print(f"idempotency: stale scope: {exc}", file=sys.stderr)
        return 0 if hook == "post-commit" else 1
    try:
        client = Client.from_env()
    except IdempotencyError as exc:
        print(f"idempotency: {exc}", file=sys.stderr)
        return 1
    exit_code = 1

    def run() -> dict:
        nonlocal exit_code
        if hook == "pre-commit":
            note_pre_commit(repo, agent)
        if hook == "post-commit":
            mark_post_commit(repo, agent)
        if preserved and os.path.isfile(preserved):
            proc = subprocess.run([preserved, *args])
            if proc.returncode < 0:
                raise UncertainOutcome("hook_signaled")
            if proc.returncode != 0:
                exit_code = proc.returncode
                raise NotApplied(str(proc.returncode))
        return {"kind": "value", "value": {"exit_code": 0}}

    try:
        client.once({"hook": hook, "kind": "hook"}, run)
    except NotApplied:
        return exit_code
    except IdempotencyError as exc:
        print(f"idempotency: {exc}", file=sys.stderr)
        return 1
    return 0


def _run_hook(name: str, preserved: str, args: list[str]) -> int:
    _at_repo()
    mode = os.environ.get("IDEMPOTENCY_HOOK_MODE", "passive")
    if mode != "active":
        try:
            status = _note(name)
        except Exception as exc:
            print(f"idempotency: scope note failed: {exc}", file=sys.stderr)
            status = 1
        if status != 0:
            print("idempotency: scope note failed; continuing", file=sys.stderr)
        return _run_preserved(preserved, args)
    return _active(name, preserved, args)


def _run_preserved(preserved: str, args: list[str]) -> int:
    if preserved and os.path.isfile(preserved):
        proc = subprocess.run([preserved, *args])
        if proc.returncode < 0:
            return 128 + abs(proc.returncode)
        return proc.returncode
    return 0


def _install_hooks() -> int:
    repo = _at_repo()
    hooks_path = _git_optional(repo, "config", "--get", "core.hooksPath")
    if hooks_path:
        dest = hooks_path if os.path.isabs(hooks_path) else os.path.join(repo, hooks_path)
    else:
        git_path = _git_optional(repo, "rev-parse", "--git-path", "hooks")
        dest = git_path if os.path.isabs(git_path) else os.path.join(repo, git_path)
    os.makedirs(dest, exist_ok=True)
    state = os.path.join(repo, ".idempotency")
    os.makedirs(state, exist_ok=True)
    agent_file = os.path.join(state, "agent-id")
    if not os.path.isfile(agent_file) or os.path.getsize(agent_file) == 0:
        with open(agent_file, "w", encoding="utf-8") as handle:
            handle.write(uuid.uuid4().hex + "\n")
    _install_hook(repo, dest, "pre-commit")
    _install_hook(repo, dest, "post-commit")
    print(f"idempotency: hooks installed in {dest}")
    return 0


def _install_hook(repo: str, dest: str, name: str) -> None:
    target = os.path.join(dest, name)
    preserved = os.path.join(dest, f"{name}.idempotency-preserved")
    if os.path.isfile(target) and not os.path.isfile(preserved):
        with open(target, encoding="utf-8", errors="replace") as handle:
            current = handle.read()
        if "IDEMPOTENCY_HOOK_CHAIN" not in current:
            shutil.copy2(target, preserved)
            os.chmod(preserved, os.stat(preserved).st_mode | 0o111)
    relative = ""
    if os.path.isfile(preserved):
        if preserved.startswith(repo + os.sep):
            relative = os.path.relpath(preserved, repo)
        else:
            relative = preserved
    _write_stub(target, name, relative)
    os.chmod(target, os.stat(target).st_mode | 0o111)


def _write_stub(target: str, name: str, relative: str) -> None:
    quoted_name = shlex.quote(name)
    quoted_relative = shlex.quote(relative)
    text = f"""#!/bin/bash
# IDEMPOTENCY_HOOK_CHAIN
ROOT="$(git rev-parse --show-toplevel)"
PRESERVED=""
RELATIVE={quoted_relative}
if [ -n "$RELATIVE" ]; then
  case "$RELATIVE" in
    /*) PRESERVED="$RELATIVE" ;;
    *) PRESERVED="$ROOT/$RELATIVE" ;;
  esac
fi
mode="${{IDEMPOTENCY_HOOK_MODE:-passive}}"
if ! command -v agent-idempotency >/dev/null 2>&1; then
  if [ "$mode" = "active" ]; then
    echo "idempotency: agent-idempotency is not on PATH" >&2
    exit 127
  fi
  echo "idempotency: agent-idempotency is not on PATH; continuing" >&2
  if [ -n "$PRESERVED" ] && [ -f "$PRESERVED" ]; then
    "$PRESERVED" "$@"
    exit $?
  fi
  exit 0
fi
exec agent-idempotency run-hook {quoted_name} "$PRESERVED" -- "$@"
"""
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(text)


if __name__ == "__main__":
    raise SystemExit(main())
