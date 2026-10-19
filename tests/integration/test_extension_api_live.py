"""Опциональные read-only/negative проверки реальной HTTP-публикации.

MCP_EXTENSION_TEST_URL — URL публикации, MCP_EXTENSION_TEST_USER/PASSWORD — учетные данные.
MCP_EXTENSION_TEST_CFE — готовый CFE; MCP_EXTENSION_TEST_NAME — его внутреннее имя.
Ни один тест не отправляет допустимый запрос установки (confirm всегда false).
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import unittest
import urllib.request


@unittest.skipUnless(os.environ.get("MCP_EXTENSION_TEST_URL"), "HTTP-стенд явно не выбран")
class ExtensionApiLiveTests(unittest.TestCase):
    def request(self, method, params):
        user = os.environ.get("MCP_EXTENSION_TEST_USER", "")
        password = os.environ.get("MCP_EXTENSION_TEST_PASSWORD", "")
        request = urllib.request.Request(
            os.environ["MCP_EXTENSION_TEST_URL"].rstrip("/") + "/hs/mcp/rpc",
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
            {"Content-Type": "application/json", "Authorization": "Basic " + base64.b64encode((user + ":" + password).encode()).decode()})
        with urllib.request.urlopen(request, timeout=60) as response:
            document = json.load(response)
        self.assertNotIn("error", document, document)
        return document["result"]

    def call(self, name, arguments):
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        return result.get("isError", False), json.loads(result["content"][0]["text"])

    def candidate(self):
        if not os.environ.get("MCP_EXTENSION_TEST_CFE"):
            self.skipTest("CFE для проверки не выбран")
        data = Path(os.environ["MCP_EXTENSION_TEST_CFE"]).read_bytes()
        return {"name": os.environ["MCP_EXTENSION_TEST_NAME"], "cfe_base64": base64.b64encode(data).decode(),
                "sha256": hashlib.sha256(data).hexdigest(), "expected_stand": "0" * 64}

    def test_tools_and_required_arguments(self):
        tools = {tool["name"]: tool for tool in self.request("tools/list", {})["tools"]}
        expected = {"extension_inspect": {"name"}, "extension_validate": {"name", "cfe_base64", "sha256", "expected_stand"},
                    "extension_install": {"name", "cfe_base64", "sha256", "expected_stand", "expected_previous_sha256", "confirm"}}
        for name, required in expected.items():
            self.assertEqual(set(tools[name]["inputSchema"]["required"]), required)
            self.assertFalse(tools[name]["inputSchema"]["additionalProperties"])
        for name in ("safe_mode", "dangerous_actions_protection"):
            self.assertEqual(tools["extension_install"]["inputSchema"]["properties"][name]["type"], "boolean")

    def test_inspection_has_distinct_stored_and_session_state(self):
        error, state = self.call("extension_inspect", {"name": os.environ.get("MCP_EXTENSION_TEST_NAME", "mcp_tools")})
        self.assertFalse(error, state)
        for name in ("stand_fingerprint", "platform_version", "configuration_version", "current_user", "session_id",
                     "stored_sha256", "stored_platform_hash", "session_platform_hash", "applied_in_current_session",
                     "safe_mode", "dangerous_actions_protection", "session_safe_mode", "session_dangerous_actions_protection"):
            self.assertIn(name, state)
        self.assertEqual(len(state["stand_fingerprint"]), 64)
        if state["applied_in_current_session"]:
            self.assertTrue(state["exists"])
            self.assertTrue(state["enabled"])
            self.assertEqual(state["stored_platform_hash"], state["session_platform_hash"])
            self.assertEqual(state["safe_mode"], state["session_safe_mode"])
            self.assertEqual(state["dangerous_actions_protection"], state["session_dangerous_actions_protection"])

    def test_invalid_stand_rejected_without_install(self):
        arguments = self.candidate()
        error, result = self.call("extension_validate", arguments)
        self.assertTrue(error, result)
        self.assertEqual(result["error_code"], "validation_failed")
        self.assertIn("stand_mismatch", result["message"])

    def test_install_requires_true_confirmation_before_any_write(self):
        arguments = self.candidate()
        arguments.update(confirm=False, expected_previous_sha256="")
        error, result = self.call("extension_install", arguments)
        self.assertTrue(error, result)
        self.assertEqual(result["error_code"], "validation_failed")
        self.assertIn("confirm", result["message"])


if __name__ == "__main__":
    unittest.main()
