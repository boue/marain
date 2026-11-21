"""The installed package carries the same Lua script as the protocol file."""

import unittest
from importlib.resources import files
from pathlib import Path


class PackagedLuaTests(unittest.TestCase):
    def test_packaged_bytes_match_the_protocol_script(self):
        packaged = files("agent_idempotency").joinpath("redis", "record.lua").read_bytes()
        protocol = Path(__file__).resolve().parents[2] / "protocol" / "redis" / "record.lua"
        self.assertEqual(packaged, protocol.read_bytes())


if __name__ == "__main__":
    unittest.main()
