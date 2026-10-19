"""Контракты MCP/HTTP без обращения к живой базе и без пользовательских test_*.py."""

import io
import json
import logging
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import httpx
from mcp import types
from mcp.server.lowlevel.server import request_ctx
from mcp.server.sse import SseServerTransport

from src.py_server.config import Config
from src.py_server.main import setup_logging
from src.py_server.mcp_server import MCPProxy
from src.py_server.onec_client import OneCClient


class ExecuteCodeProxyTests(unittest.IsolatedAsyncioTestCase):
	async def asyncSetUp(self):
		self.requests = []
		self.response_result = {
			"content": [{"type": "text", "text": '{"execution_id":"test-id","result":"result-secret"}'}],
			"isError": False,
		}
		self.failure = None

		def transport(request):
			self.requests.append(json.loads(request.content))
			if self.failure:
				raise self.failure
			return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": self.response_result})

		with patch.object(OneCClient, "_create_client", return_value=httpx.AsyncClient(transport=httpx.MockTransport(transport))):
			self.client = OneCClient("http://test.invalid/base", "", "")

	async def asyncTearDown(self):
		await self.client.close()

	async def test_sensitive_payload_reaches_server_but_not_debug_log(self):
		arguments = {"code": 'Результат = "code-secret";', "parameters": {"password": "parameter-secret"}}
		with self.assertLogs("src.py_server.onec_client", level="DEBUG") as logs:
			result = await self.client.call_tool("execute_code", arguments)
		self.assertEqual(self.requests[0]["params"]["arguments"], arguments)
		self.assertIn("result-secret", result.content[0].text)
		self.assertFalse(result.isError)
		for secret in ("code-secret", "parameter-secret", "result-secret"):
			self.assertNotIn(secret, "\n".join(logs.output))

	async def test_old_query_response_is_preserved(self):
		self.response_result = {"content": [{"type": "text", "text": "query-result"}], "isError": False}
		result = await self.client.call_tool("execute_query", {"query": "ВЫБРАТЬ 1"})
		self.assertEqual(result.content[0].text, "query-result")
		self.assertFalse(result.isError)

	async def test_extension_payload_and_backup_path_are_hidden_from_debug(self):
		for tool in ("extension_validate", "extension_install"):
			with self.subTest(tool=tool):
				self.response_result = {"content": [{"type": "text", "text": '{"backup_path":"backup-secret"}'}], "isError": False}
				with self.assertLogs("src.py_server.onec_client", level="DEBUG") as logs:
					result = await self.client.call_tool(tool, {"cfe_base64": "CFE_SOURCE_SECRET"})
				self.assertIn("backup-secret", result.content[0].text)
				self.assertNotIn("backup-secret", "\n".join(logs.output))
				self.assertNotIn("CFE_SOURCE_SECRET", "\n".join(logs.output))

	async def test_extension_install_transport_failure_has_no_retry_or_payload_leak(self):
		self.failure = httpx.ReadTimeout("extension-transport-secret")
		with self.assertLogs("src.py_server", level="DEBUG") as logs:
			result = await self.dispatch(self.client, "extension_install")
		self.assertTrue(result.isError)
		self.assertIn("Не повторяйте", result.content[0].text)
		self.assertEqual(len(self.requests), 1)
		self.assertNotIn("extension-transport-secret", "\n".join(logs.output))
		self.assertNotIn("proxy-secret", "\n".join(logs.output))

	async def test_http_timeout_is_not_retried_and_does_not_log_error_payload(self):
		self.failure = httpx.ReadTimeout("exception-secret")
		with self.assertLogs("src.py_server.onec_client", level="DEBUG") as logs:
			with self.assertRaises(httpx.ReadTimeout):
				await self.client.call_tool("execute_code", {"code": "code-secret"})
		self.assertEqual(len(self.requests), 1)
		self.assertNotIn("exception-secret", "\n".join(logs.output))
		self.assertNotIn("code-secret", "\n".join(logs.output))

	async def dispatch(self, client, tool="execute_code"):
		config = Config(_env_file=None, onec_url="http://test.invalid/base", onec_username="", onec_password="")
		proxy = MCPProxy(config)
		client.list_tools = AsyncMock(return_value=[types.Tool(name=tool, inputSchema={"type": "object"})])
		token = request_ctx.set(SimpleNamespace(lifespan_context={"onec_client": client}))
		try:
			response = await proxy.server.request_handlers[types.CallToolRequest](
				types.CallToolRequest(method="tools/call", params=types.CallToolRequestParams(
					name=tool, arguments={"code": "proxy-secret"}
				))
			)
			return response.root
		finally:
			request_ctx.reset(token)

	async def test_is_error_survives_actual_sdk_dispatch(self):
		self.response_result["isError"] = True
		with self.assertLogs("src.py_server", level="DEBUG") as logs:
			result = await self.dispatch(self.client)
		self.assertTrue(result.isError)
		self.assertEqual(result.content[0].text, self.response_result["content"][0]["text"])
		self.assertNotIn("proxy-secret", "\n".join(logs.output))
		self.assertNotIn("result-secret", "\n".join(logs.output))

	async def test_old_tool_success_survives_actual_sdk_dispatch(self):
		result = await self.dispatch(self.client, "execute_query")
		self.assertFalse(result.isError)
		self.assertEqual(result.content[0].text, self.response_result["content"][0]["text"])

	async def test_transport_failure_is_explicit_error_with_unknown_outcome(self):
		self.failure = httpx.ReadTimeout("transport-secret")
		with self.assertLogs("src.py_server", level="DEBUG") as logs:
			result = await self.dispatch(self.client)
		self.assertTrue(result.isError)
		self.assertIn("Не повторяйте", result.content[0].text)
		self.assertEqual(len(self.requests), 1)
		self.assertNotIn("transport-secret", "\n".join(logs.output))
		self.assertNotIn("transport-secret", result.content[0].text)

	def test_debug_mode_does_not_enable_sdk_payload_logging(self):
		logger = logging.getLogger("mcp")
		previous_level = logger.level
		try:
			with patch("src.py_server.main.logging.basicConfig"):
				setup_logging("DEBUG")
			self.assertFalse(logging.getLogger("mcp.server.lowlevel.server").isEnabledFor(logging.DEBUG))
		finally:
			logger.setLevel(previous_level)

	async def test_malformed_sse_payload_is_hidden_in_existing_and_child_handlers(self):
		# Настоящий SDK parser: ValidationError раньше обходил запрет DEBUG
		# и выводил BSL в logger.exception(ERROR), до обработчика инструмента.
		root = logging.getLogger()
		sdk = logging.getLogger("mcp")
		child = logging.getLogger("mcp.server.sse")
		original_root = (root.handlers[:], root.level)
		original_child = (child.handlers[:], child.level, child.propagate)
		original_sdk_level = sdk.level
		try:
			for propagate in (False, True):
				with self.subTest(propagate=propagate):
					root_output, child_output = io.StringIO(), io.StringIO()
					root.handlers = [logging.StreamHandler(root_output)]
					root.setLevel(logging.DEBUG)
					child.handlers = [logging.StreamHandler(child_output)]
					child.setLevel(logging.NOTSET)
					child.propagate = propagate
					# basicConfig не заменяет существующий root handler.
					setup_logging("DEBUG")
					transport = SseServerTransport("/messages/")
					transport._security.validate_request = AsyncMock(return_value=None)
					session_id = uuid4()
					writer = AsyncMock()
					transport._read_stream_writers[session_id] = writer
					payload = {
						"jsonrpc": "broken", "id": 1, "method": "tools/call",
						"params": {"name": "execute_code", "arguments": {"code": "PAYLOAD_AUDIT_SECRET"}},
					}
					receive = AsyncMock(return_value={
						"type": "http.request", "body": json.dumps(payload).encode(), "more_body": False,
					})
					send = AsyncMock()
					await transport.handle_post_message({
						"type": "http", "method": "POST", "path": "/messages/",
						"query_string": f"session_id={session_id.hex}".encode(), "headers": [],
					}, receive, send)
					self.assertEqual(send.call_args_list[0].args[0]["status"], 400)
					# Подтверждаем, что именно исключение с payload дошло из parser.
					self.assertIn("PAYLOAD_AUDIT_SECRET", str(writer.send.call_args.args[0]))
					for output in (root_output.getvalue(), child_output.getvalue()):
						self.assertNotIn("PAYLOAD_AUDIT_SECRET", output)
						self.assertNotIn("Traceback", output)
					self.assertIn("Событие MCP SDK", child_output.getvalue())
					self.assertEqual("Событие MCP SDK" in root_output.getvalue(), propagate)
					logging.getLogger("src.py_server.mcp_server").warning("Состояние прокси сохранено")
					self.assertIn("Состояние прокси сохранено", root_output.getvalue())
		finally:
			root.handlers, root.level = original_root
			child.handlers, child.level, child.propagate = original_child
			sdk.setLevel(original_sdk_level)


if __name__ == "__main__":
	unittest.main()
