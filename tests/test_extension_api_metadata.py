"""Проверка регистрации объектов и границы прав API установки расширений."""
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1] / "src/1c_ext"
NS = {"m": "http://v8.1c.ru/8.3/MDClasses", "r": "http://v8.1c.ru/8.2/roles"}
CONSTANTS = {"mcp_УстановкаРасширенийРазрешена", "mcp_СтендУстановкиРасширений", "mcp_КаталогКопийРасширений"}
ROLES = {"mcp_ЧтениеРасширений", "mcp_УстановкаРасширений", "mcp_НастройкаУстановкиРасширений"}
PROCESSOR = "mcp_ИнструментУстановкаРасширений"


class ExtensionMetadataTests(unittest.TestCase):
    def rights(self, role):
        root = ET.parse(ROOT / "Roles" / role / "Ext/Rights.xml").getroot()
        self.assertEqual(root.findtext("r:setForNewObjects", namespaces=NS), "false")
        return {obj.findtext("r:name", namespaces=NS): {
            right.findtext("r:name", namespaces=NS): right.findtext("r:value", namespaces=NS)
            for right in obj.findall("r:right", NS)} for obj in root.findall("r:object", NS)}

    def test_probe_and_installer_cannot_change_policy(self):
        for role in ("mcp_ЧтениеРасширений", "mcp_УстановкаРасширений"):
            rights = self.rights(role)
            for name in CONSTANTS:
                self.assertEqual(rights[f"Constant.{name}"]["Read"], "true")
                self.assertEqual(rights[f"Constant.{name}"]["Update"], "false")
                self.assertEqual(rights[f"Constant.{name}"]["Edit"], "false")
            self.assertFalse(any(name.startswith("Configuration.") for name in rights))

    def test_setup_role_only_changes_extension_policy(self):
        rights = self.rights("mcp_НастройкаУстановкиРасширений")
        self.assertEqual(set(rights), {f"Constant.{name}" for name in CONSTANTS} | {f"DataProcessor.{PROCESSOR}"})
        for name in CONSTANTS:
            self.assertEqual(rights[f"Constant.{name}"]["Update"], "true")

    def test_constants_are_accessible_to_manual_bootstrap(self):
        for name in CONSTANTS:
            root = ET.parse(ROOT / "Constants" / (name + ".xml")).getroot()
            self.assertEqual(root.findtext("m:Constant/m:Properties/m:UseStandardCommands", namespaces=NS), "true")
        root = ET.parse(ROOT / "Constants/mcp_УстановкаРасширенийРазрешена.xml").getroot()
        self.assertEqual(root.findtext("m:Constant/m:Properties/m:Type/{http://v8.1c.ru/8.1/data/core}Type", namespaces=NS), "xs:boolean")

    def test_all_objects_registered_once_with_unique_identifiers(self):
        root = ET.parse(ROOT / "Configuration.xml").getroot()
        children = root.find("m:Configuration/m:ChildObjects", NS)
        for kind, names in {"Constant": CONSTANTS, "Role": ROLES, "DataProcessor": {PROCESSOR}}.items():
            registered = [node.text for node in children.findall(f"m:{kind}", NS)]
            for name in names:
                self.assertEqual(registered.count(name), 1)
                self.assertTrue((ROOT / f"{kind}s" / (name + ".xml")).exists())
        identifiers = []
        for path in ROOT.rglob("*.xml"):
            doc = ET.parse(path).getroot()
            identifiers += [node.attrib["uuid"] for node in doc if "uuid" in node.attrib]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        subsystem = ET.parse(ROOT / "Subsystems/mcp_MCPСервер/Subsystems/mcp_КонтейнерыИнструментов.xml").getroot()
        self.assertEqual([item.text for item in subsystem.iter()].count(f"DataProcessor.{PROCESSOR}"), 1)

    def test_unconfirmed_exclusive_release_is_unknown_even_before_write(self):
        source = (ROOT / f"DataProcessors/{PROCESSOR}/Ext/ManagerModule.bsl").read_text(encoding="utf-8-sig")
        # Регрессия протокола: rejected снимает карантин у клиента. Ошибка освобождения
        # должна сохранять unknown даже когда Записать ещё не вызывалась.
        failure = source[source.index("ОсвобождениеПодтверждено = Истина;"):source.index("Возврат Ответ(ОтветОшибки, Истина);")]
        self.assertIn("ОсвобождениеПодтверждено = Ложь;", failure)
        self.assertIn("ИсходНеизвестен = ЗаписьНачата Или Не ОсвобождениеПодтверждено;", failure)
        self.assertIn('?(ИсходНеизвестен, "unknown", "rejected")', failure)
        self.assertIn('"exclusive_release_unknown"', failure)

    def test_successful_write_with_release_failure_keeps_backup_and_unknown(self):
        source = (ROOT / f"DataProcessors/{PROCESSOR}/Ext/ManagerModule.bsl").read_text(encoding="utf-8-sig")
        after_catch = source[source.index("Возврат Ответ(ОтветОшибки, Истина);"):source.index("Функция SHA256")]
        self.assertIn('Идентификатор, "unknown", "exclusive_release_unknown"', after_catch)
        self.assertIn('backup_path, backup_sha256', after_catch)
        self.assertIn('ПутьКопии, ХешКопии), Истина);', after_catch)
        self.assertNotIn('Возврат Ошибка("exclusive_release_unknown"', after_catch)

    def test_file_access_failure_is_safe_rejection_before_exclusive_mode(self):
        source = (ROOT / f"DataProcessors/{PROCESSOR}/Ext/ManagerModule.bsl").read_text(encoding="utf-8-sig")
        preflight = source[source.index('ЭтапУстановки = "backup_directory_check";'):source.index('ЭтапУстановки = "exclusive_acquire";')]
        self.assertIn("Попытка", preflight)
        self.assertIn("Исключение", preflight)
        self.assertIn('Возврат Ошибка("backup_directory_unavailable"', preflight)
        self.assertNotIn("ОписаниеОшибки()", preflight)
        self.assertNotIn(".Записать(", preflight)
        self.assertNotIn("УстановитьМонопольныйРежим(", preflight)

    def test_extension_settings_are_optional_explicit_and_checked_in_session(self):
        source = (ROOT / f"DataProcessors/{PROCESSOR}/Ext/ManagerModule.bsl").read_text(encoding="utf-8-sig")
        for name in ("safe_mode", "dangerous_actions_protection"):
            self.assertIn(f'Аргументы.Свойство("{name}", Настройка)', source)
            self.assertIn(f'Результат.Вставить("session_{name}", Неопределено)', source)
            self.assertIn(f'Результат.session_{name} = Результат.{name}', source)
        self.assertIn('ТипЗнч(Настройка) <> Тип("Булево")', source)


if __name__ == "__main__":
    unittest.main()
