"""Claim one Redis key from an installed wheel, outside the source checkout."""

import os
import sys

from agent_idempotency.store import RedisStore, lua_script


def main() -> int:
    script = lua_script()
    if "claim" not in script:
        print("packaged lua is missing claim", file=sys.stderr)
        return 1
    store = RedisStore(os.environ["IDEMPOTENCY_TEST_REDIS_URL"])
    claimed = store.call("claim", "ab" * 32, owner="ci", body="{}")
    if claimed.get("status") != "claimed":
        print(claimed, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
