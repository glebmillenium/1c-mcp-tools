"""Verify outgoing authentication headers using an in-memory HTTP transport."""

import base64
import unittest
from unittest.mock import patch

import httpx

from src.py_server.onec_client import OneCClient


class OneCClientAuthTests(unittest.IsolatedAsyncioTestCase):
	async def asyncSetUp(self):
		self.requests = []
		self.http_clients = []
		self.real_async_client = httpx.AsyncClient
		self.client_factory = patch(
			"src.py_server.onec_client.httpx.AsyncClient",
			side_effect=self._create_mock_client,
		)
		self.client_factory.start()
		self.addCleanup(self.client_factory.stop)
		self.addAsyncCleanup(self._close_http_clients)

	def _create_mock_client(self, *args, **kwargs):
		# Keep the production _create_client() method and its auth argument.
		# Replace only transport, including clients recreated after close().
		kwargs["transport"] = httpx.MockTransport(self._respond)
		kwargs["trust_env"] = False
		client = self.real_async_client(*args, **kwargs)
		self.http_clients.append(client)
		return client

	def _respond(self, request):
		self.requests.append(request)
		self.assertEqual(request.method, "POST")
		self.assertEqual(str(request.url), "https://example.test/base/hs/mcp/rpc")
		return httpx.Response(
			200,
			json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}},
		)

	async def _close_http_clients(self):
		for client in self.http_clients:
			await client.aclose()

	async def _request_tools(self, username, password):
		client = OneCClient("https://example.test/base", username, password)
		self.assertEqual(await client.call_rpc("tools/list"), {"tools": []})
		return client

	@staticmethod
	def _basic_header(username, password):
		credentials = f"{username}:{password}".encode("ascii")
		return "Basic " + base64.b64encode(credentials).decode("ascii")

	async def test_empty_username_omits_authorization(self):
		for password in ("", "dummy-password"):
			with self.subTest(password_is_empty=not password):
				await self._request_tools("", password)
				self.assertNotIn("Authorization", self.requests[-1].headers)
		self.assertEqual(len(self.requests), 2)

	async def test_username_with_empty_password_sends_basic_auth(self):
		await self._request_tools("dummy-user", "")
		self.assertEqual(len(self.requests), 1)
		self.assertEqual(
			self.requests[0].headers["Authorization"],
			self._basic_header("dummy-user", ""),
		)

	async def test_username_and_password_send_basic_auth(self):
		await self._request_tools("dummy-user", "dummy-password")
		self.assertEqual(len(self.requests), 1)
		self.assertEqual(
			self.requests[0].headers["Authorization"],
			self._basic_header("dummy-user", "dummy-password"),
		)

	async def test_reopened_client_preserves_authorization_behavior(self):
		for username, password in (("", ""), ("dummy-user", "dummy-password")):
			with self.subTest(authenticated=bool(username)):
				client = await self._request_tools(username, password)
				closed_client = client.client
				await client.close()
				self.assertTrue(closed_client.is_closed)

				self.assertEqual(await client.call_rpc("tools/list"), {"tools": []})
				self.assertIsNot(client.client, closed_client)
				self.assertFalse(client.client.is_closed)
				expected = self._basic_header(username, password) if username else None
				self.assertEqual(self.requests[-2].headers.get("Authorization"), expected)
				self.assertEqual(self.requests[-1].headers.get("Authorization"), expected)
		self.assertEqual(len(self.requests), 4)
		self.assertEqual(len(self.http_clients), 4)


if __name__ == "__main__":
	unittest.main()
