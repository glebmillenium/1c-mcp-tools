"""Явный прогон без бизнес-записей. Запускается отдельно после настройки стенда."""

import json
import os
import unittest

from src.py_server.onec_client import OneCClient


STATE = os.environ.get("MCP_TEST_EXECUTE_CODE_STATE", "")
URL = os.environ.get("MCP_TEST_URL", "")


@unittest.skipUnless(STATE and URL, "Не задан согласованный стенд и ожидаемое состояние допуска")
class ExecuteCodeLiveTests(unittest.IsolatedAsyncioTestCase):
	async def asyncSetUp(self):
		self.assertIn(STATE, {"enabled", "disabled", "role_required", "overprivileged_account", "stand_mismatch"})
		self.client = OneCClient(URL, os.environ.get("MCP_TEST_USERNAME", ""), os.environ.get("MCP_TEST_PASSWORD", ""))

	async def asyncTearDown(self):
		await self.client.close()

	async def call(self, code, **kwargs):
		result = await self.client.call_tool("execute_code", {"code": code, **kwargs})
		payload = json.loads(result.content[0].text)
		self.assertTrue(payload["execution_id"])
		return result, payload

	async def test_policy_and_calculation(self):
		result, payload = await self.call("Результат = 6 * 7;")
		if STATE == "enabled":
			self.assertFalse(result.isError)
			self.assertEqual(payload["result"], 42)
		else:
			self.assertTrue(result.isError)
			self.assertEqual(payload["error_code"], STATE)

	@unittest.skipUnless(STATE == "enabled", "Требуется включённый допуск")
	async def test_parameters_and_safe_mode(self):
		result, payload = await self.call(
			'Результат = Новый Структура("Значение, БезопасныйРежим", Параметры.Значение, БезопасныйРежим());',
			parameters={"Значение": 7},
		)
		self.assertFalse(result.isError)
		self.assertEqual(payload["result"], {"Значение": 7, "БезопасныйРежим": True})

	@unittest.skipUnless(STATE == "enabled", "Требуется включённый допуск")
	async def test_exception_and_syntax_error(self):
		for code in ('ВызватьИсключение "Проверка execute_code";', 'Если Тогда'):
			with self.subTest(code=code):
				result, payload = await self.call(code)
				self.assertTrue(result.isError)
				self.assertEqual(payload["error_code"], "execution_failed")

	@unittest.skipUnless(STATE == "enabled", "Требуется включённый допуск")
	async def test_limits_and_unknown_parameter(self):
		for code, kwargs, expected in [
			("//" + "x" * 1000000, {}, "invalid_code"),
			("Результат = 1;", {"enable": True}, "invalid_arguments"),
			("Результат = 1;", {"parameters": {"text": "x" * 1000001}}, "invalid_parameters"),
			('Результат = "x"; Для Индекс = 1 По 20 Цикл Результат = Результат + Результат; КонецЦикла;', {}, "result_too_large"),
		]:
			with self.subTest(expected=expected):
				result, payload = await self.call(code, **kwargs)
				self.assertTrue(result.isError)
				self.assertEqual(payload["error_code"], expected)


if __name__ == "__main__":
	unittest.main()
