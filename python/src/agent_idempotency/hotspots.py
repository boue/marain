"""Hotspot report: rank resources by agent diversity and flag duplicate operations."""

import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timedelta

from agent_idempotency.audit import claims_log


def read_claims(path: str | None = None, since_days: int = 7) -> list[dict]:
    """Read claims.jsonl and filter by time window."""
    log_path = path or claims_log()
    if not os.path.isfile(log_path):
        return []
    cutoff = datetime.now() - timedelta(days=since_days)
    claims = []
    with open(log_path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                claim = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = claim.get("ts", 0)
            if ts >= cutoff.timestamp():
                claims.append(claim)
    return claims


def hotspots(claims: list[dict], min_agents: int = 2, agent_filter: str | None = None) -> list[dict]:
    """Group claims by resource_key, count distinct agents, flag duplicate operations."""
    by_resource = defaultdict(list)
    for claim in claims:
        if agent_filter and claim.get("agent_id") != agent_filter:
            continue
        by_resource[claim.get("resource_key", "")].append(claim)

    results = []
    for resource_key, resource_claims in by_resource.items():
        agents = {c.get("agent_id", "") for c in resource_claims}
        if len(agents) < min_agents:
            continue

        # Group by operation_id to find duplicates across scopes
        by_operation = defaultdict(list)
        for claim in resource_claims:
            by_operation[claim.get("operation_id", "")].append(claim)

        operations = []
        duplicate_count = 0
        for op_id, op_claims in by_operation.items():
            scopes = {c.get("scope_id", "") for c in op_claims}
            outcomes = [c.get("outcome", "") for c in op_claims]
            is_duplicate = len(scopes) > 1
            if is_duplicate:
                duplicate_count += 1
            operations.append({
                "operation_id": op_id,
                "scopes": sorted(scopes),
                "scope_count": len(scopes),
                "outcomes": outcomes,
                "duplicate": is_duplicate,
            })

        results.append({
            "resource_key": resource_key,
            "agents": sorted(agents),
            "agent_count": len(agents),
            "operations": operations,
            "duplicate_operations": duplicate_count,
        })

    # Sort by agent count descending, then by duplicate operations
    results.sort(key=lambda r: (r["agent_count"], r["duplicate_operations"]), reverse=True)
    return results


def format_table(results: list[dict]) -> str:
    """Human-readable table for stderr."""
    if not results:
        return "No hotspots found."
    lines = []
    lines.append(f"{'Resource Key':<60} {'Agents':<8} {'Duplicates':<12}")
    lines.append("-" * 82)
    for r in results:
        lines.append(f"{r['resource_key']:<60} {r['agent_count']:<8} {r['duplicate_operations']:<12}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="agent-idempotency hotspots")
    parser.add_argument("--since", default="7d", help="Time window: 24h, 7d, 30d, or ISO8601")
    parser.add_argument("--agent", default="", help="Filter to one agent")
    parser.add_argument("--min-agents", type=int, default=2, help="Minimum agents to show")
    parser.add_argument("--log", default="", help="Path to claims.jsonl")
    args = parser.parse_args(argv)

    # Parse --since
    since = args.since
    if since.endswith("d"):
        since_days = int(since[:-1])
    elif since.endswith("h"):
        since_days = int(since[:-1]) / 24
    else:
        # Try ISO8601
        try:
            dt = datetime.fromisoformat(since)
            since_days = (datetime.now() - dt).days
        except ValueError:
            print(f"agent-idempotency: invalid --since: {since}", file=sys.stderr)
            return 1

    claims = read_claims(args.log or None, since_days=int(since_days))
    results = hotspots(claims, min_agents=args.min_agents, agent_filter=args.agent or None)

    # JSON to stdout
    print(json.dumps(results, indent=2))

    # Table to stderr
    print(format_table(results), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
