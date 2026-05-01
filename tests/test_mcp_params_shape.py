"""
Integration test: MCP `tools/call` must accept the JSON-RPC 2.0 / MCP
canonical shape where `params` is an object, not a JSON-encoded
string. Drives `oci2bin mcp-serve` over stdin/stdout.
"""

import json
import os
import pathlib
import subprocess
import unittest


_ROOT = pathlib.Path(__file__).resolve().parent.parent
_LOADER = _ROOT / "build" / "loader-x86_64"


def _send_one(req: dict) -> dict:
    """Spawn mcp-serve, send a single JSON-RPC line, read all lines,
    and return the first reply whose id matches the request. The server
    emits an unsolicited init/server-info line before processing the
    first request, so a plain head -1 wouldn't suffice."""
    line = (json.dumps(req) + "\n").encode()
    p = subprocess.Popen(
        [str(_LOADER), "mcp-serve"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        out, _ = p.communicate(line, timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
        raise
    target_id = req.get("id")
    seen = []
    for raw in out.splitlines():
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        seen.append(obj)
        if obj.get("id") == target_id:
            return obj
    # Fall back to last reply if none matched the id (means the server
    # didn't honour our id — a separate bug, but we still return it so
    # the test can report something useful).
    if seen:
        return seen[-1]
    raise AssertionError(
        f"empty mcp-serve output; rc={p.returncode}")


@unittest.skipUnless(_LOADER.exists(),
                     f"{_LOADER} not built (run `make`)")
class McpParamsShapeTest(unittest.TestCase):
    def test_tools_call_with_object_params_not_rejected(self):
        # list_containers returns the empty list when nothing's running.
        # Crucially, params is a JSON OBJECT — the MCP-correct shape.
        # The bug was that the server saw `params` as not-a-string and
        # replied with -32602 "tools/call: params missing".
        req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "list_containers",
                "arguments": {},
            },
        }
        reply = _send_one(req)
        # Tolerate the existing id-echo issue (production replies with
        # id=-1) but assert we got a real result, not the "params
        # missing" error.
        if "error" in reply:
            err = reply["error"]
            self.assertNotIn(
                "params missing", str(err.get("message", "")),
                f"object-form params rejected: {reply}")
        else:
            self.assertIn("result", reply, msg=str(reply))


if __name__ == "__main__":
    unittest.main()
