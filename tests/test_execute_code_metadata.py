"""Проверка прав и регистрации новых метаданных. Не заменяет компиляцию 1С."""

from pathlib import Path
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1] / "src/1c_ext"
MD = {"m": "http://v8.1c.ru/8.3/MDClasses", "r": "http://v8.1c.ru/8.2/roles"}
CONSTANTS = {"mcp_ВыполнениеКодаРазрешено", "mcp_ОтпечатокТестовойБазы"}


class ExecuteCodeMetadataTests(unittest.TestCase):
	def rights(self, role):
		root = ET.parse(ROOT / "Roles" / role / "Ext/Rights.xml").getroot()
		self.assertEqual(root.findtext("r:setForNewObjects", namespaces=MD), "false")
		return {
			obj.findtext("r:name", namespaces=MD): {
				right.findtext("r:name", namespaces=MD): right.findtext("r:value", namespaces=MD)
				for right in obj.findall("r:right", MD)
			}
			for obj in root.findall("r:object", MD)
		}

	def test_executor_cannot_enable_or_rebind_policy(self):
		rights = self.rights("mcp_ВыполнениеКода")
		for name in CONSTANTS:
			self.assertEqual(rights[f"Constant.{name}"]["Read"], "true")
			self.assertEqual(rights[f"Constant.{name}"]["Update"], "false")
			self.assertEqual(rights[f"Constant.{name}"]["Edit"], "false")
		self.assertFalse(any(name.startswith("Configuration.") for name in rights))

	def test_policy_admin_has_only_explicit_settings_rights(self):
		rights = self.rights("mcp_НастройкаВыполненияКода")
		self.assertEqual(set(rights), {f"Constant.{name}" for name in CONSTANTS} | {"DataProcessor.mcp_ИнструментВыполнениеКода"})
		for name in CONSTANTS:
			self.assertEqual(rights[f"Constant.{name}"]["Update"], "true")

	def test_new_objects_are_registered_and_all_xml_is_well_formed(self):
		for path in ROOT.rglob("*.xml"):
			ET.parse(path)
		root = ET.parse(ROOT / "Configuration.xml").getroot()
		children = root.find("m:Configuration/m:ChildObjects", MD)
		for kind, names in {
			"Constant": CONSTANTS,
			"Role": {"mcp_ВыполнениеКода", "mcp_НастройкаВыполненияКода"},
			"DataProcessor": {"mcp_ИнструментВыполнениеКода"},
		}.items():
			registered = [node.text for node in children.findall(f"m:{kind}", MD)]
			for name in names:
				self.assertEqual(registered.count(name), 1)
				self.assertTrue((ROOT / f"{kind}s" / f"{name}.xml").exists())
		subsystem = ET.parse(ROOT / "Subsystems/mcp_MCPСервер/Subsystems/mcp_КонтейнерыИнструментов.xml").getroot()
		self.assertEqual([item.text for item in subsystem.iter()].count("DataProcessor.mcp_ИнструментВыполнениеКода"), 1)


if __name__ == "__main__":
	unittest.main()
