"""Собственный одноразовый localhost-стенд extension API (Windows, 1С 8.3.27+).

Запуск только с --confirm-disposable. Никогда не принимает путь к существующей ИБ.
Не использует execute_code; фиксированный bootstrap находится в tests/fixtures.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/extension-api"


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_manifest():
    paths = [path for folder in (ROOT / "src/1c_ext", FIXTURE) for path in sorted(folder.rglob("*")) if path.is_file()]
    paths.append(Path(__file__).resolve())
    return [{"path": path.relative_to(ROOT).as_posix(), "sha256": sha(path)} for path in paths]


def hidden():
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    return {"startupinfo": startup, "creationflags": subprocess.CREATE_NO_WINDOW}


def run_command(run, name, args):
    with (run / (name + ".log")).open("wb") as log:
        result = subprocess.run([str(arg) for arg in args], stdout=log, stderr=subprocess.STDOUT,
                                input=b"y\n" if "apply" in args else None, timeout=300, **hidden())
    print(json.dumps({"step": name, "exit_code": result.returncode}), flush=True)
    if result.returncode:
        raise RuntimeError(f"{name}: exit {result.returncode}; см. {run / (name + '.log')}")


def prepare(run, platform):
    fixture = run / "inputs/fixture"
    source = run / "inputs/mcp"
    command = [platform / "ibcmd.exe", "infobase", f"--data={run / 'server-data'}", f"--db-path={run / 'database'}"]
    run_command(run, "create", command + ["create", "--locale=ru_RU"])
    run_command(run, "base-import", command + ["config", "import", fixture / "base"])
    run_command(run, "base-apply", command + ["config", "apply"])
    # Production API is built from the actual final source, not an earlier CFE.
    designer = [platform / "1cv8.exe", "DESIGNER", "/F", run / "database", "/DisableStartupDialogs", "/DisableStartupMessages"]
    # Импорт этого расширения через ibcmd может зависать на 8.3.27.2130.
    # Этот маршрут Designer подтверждён полным HTTP-пилотом; сеансы не завершаем.
    run_command(run, "mcp-import-designer", designer + ["/Out", run / "mcp-import-designer.designer.log",
                "/LoadConfigFromFiles", source, "-Extension", "mcp_tools"])
    run_command(run, "mcp-apply-designer", designer + ["/Out", run / "mcp-apply-designer.designer.log",
                "/UpdateDBCfg", "-Extension", "mcp_tools", "-SessionTerminate", "disable"])
    for name, extension in [("base", []), ("mcp", ["-Extension", "mcp_tools"])]:
        run_command(run, name + "-check", designer + ["/Out", run / (name + "-check.designer.log"),
                    "/CheckModules", "-Server", "-ExternalConnection", "-ExtendedModulesCheck", *extension])
    run_command(run, "mcp-save-designer", designer + ["/Out", run / "mcp-save-designer.designer.log",
                "/DumpCfg", run / "mcp_tools.cfe", "-Extension", "mcp_tools"])
    # Candidate is compiled in a DIFFERENT blank build database: pilot starts with it absent.
    payload_command = [platform / "ibcmd.exe", "infobase", f"--data={run / 'payload-server-data'}", f"--db-path={run / 'payload-database'}"]
    run_command(run, "payload-create", payload_command + ["create", "--locale=ru_RU"])
    run_command(run, "payload-import-v1", payload_command + ["config", "import", "--extension=FixturePayload", fixture / "payload"])
    run_command(run, "payload-save-v1", payload_command + ["config", "save", "--extension=FixturePayload", run / "payload-v1.cfe"])
    version2 = run / "payload-v2-source"
    shutil.copytree(fixture / "payload", version2)
    for relative, old, new in [("Configuration.xml", "<Version>1.0.0</Version>", "<Version>1.0.1</Version>"),
                               ("CommonModules/fixture_Payload/Ext/Module.bsl", "fixture-v1", "fixture-v2")]:
        path = version2 / relative
        path.write_text(path.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")
    run_command(run, "payload-import-v2", payload_command + ["config", "import", "--extension=FixturePayload", version2])
    run_command(run, "payload-save-v2", payload_command + ["config", "save", "--extension=FixturePayload", run / "payload-v2.cfe"])


def publication(run, platform, apache):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    www = run / "www"
    www.mkdir()
    connection = escape(f'File="{run / "database"}";', {'"': "&quot;"})
    descriptor = (f'<point xmlns="http://v8.1c.ru/8.2/virtual-resource-system" base="/fixture" '
                  f'ib="{connection}">'
                  '<ws pointEnableCommon="false" publishExtensionsByDefault="false"/>'
                  '<httpServices publishByDefault="false" publishExtensionsByDefault="false">'
                  '<service name="mcp_APIBackend" rootUrl="mcp" enable="true" reuseSessions="dontuse" sessionMaxAge="1"/>'
                  '<service name="FixtureBootstrap" rootUrl="fixture" enable="true"/>'
                  '</httpServices><standardOdata enable="false"/><pool maxAge="1"/></point>')
    (www / "default.vrd").write_text(descriptor, encoding="utf-8")
    conf = f'''ServerRoot "{apache.parent.parent.as_posix()}"
Listen 127.0.0.1:{port}
ServerName 127.0.0.1:{port}
ServerTokens Prod
ServerSignature Off
PidFile "{(run / 'apache.pid').as_posix()}"
ErrorLog "{(run / 'apache-error.log').as_posix()}"
LogLevel warn
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule authz_host_module modules/mod_authz_host.so
LoadModule alias_module modules/mod_alias.so
LoadModule dir_module modules/mod_dir.so
LoadModule mime_module modules/mod_mime.so
LoadModule _1cws_module "{(platform / 'wsap24.dll').as_posix()}"
TypesConfig conf/mime.types
ThreadsPerChild 8
MaxConnectionsPerChild 0
Timeout 120
KeepAlive Off
DocumentRoot "{www.as_posix()}"
<Directory />
 AllowOverride None
 Require all denied
</Directory>
Alias "/fixture" "{www.as_posix()}/"
<Directory "{www.as_posix()}/">
 AllowOverride None
 Options None
 Require local
 SetHandler 1c-application
 ManagedApplicationDescriptor "{(www / 'default.vrd').as_posix()}"
</Directory>
'''
    (run / "httpd.conf").write_text(conf, encoding="utf-8")
    run_command(run, "apache-check", [apache, "-t", "-f", run / "httpd.conf"])
    return port


class Pilot:
    def __init__(self, run, port):
        self.run = run
        self.url = f"http://127.0.0.1:{port}/fixture"
        self.counter = 0

    def request(self, path, data=None, user="FixtureOperator"):
        headers = {"Content-Type": "application/json", "Connection": "close"}
        if user:
            headers["Authorization"] = "Basic " + base64.b64encode((user + ":").encode()).decode()
        # No cookie jar: 1C must create a new service session, checked using actual session_id below.
        request = urllib.request.Request(self.url + path, data, headers)
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            # Private diagnostics of this artificial fixture, never printed or sent to MCP clients.
            target = self.run / ("fixture-http-error-" + uuid.uuid4().hex + ".txt")
            target.write_bytes(error.read())
            raise RuntimeError(f"HTTP {error.code}; local fixture diagnostics: {target.name}") from None

    def call(self, name, arguments, label, user="FixtureOperator"):
        self.counter += 1
        raw = self.request("/hs/mcp/rpc", json.dumps({"jsonrpc": "2.0", "id": self.counter,
                           "method": "tools/call", "params": {"name": name, "arguments": arguments}}).encode(), user)
        envelope = json.loads(raw)
        save(self.run / (label + ".json"), envelope)
        if "error" in envelope:
            raise RuntimeError(f"{label}: JSON-RPC error: {envelope['error']}")
        content = envelope["result"]
        value = json.loads(content["content"][0]["text"])
        print(json.dumps({"step": label, "is_error": content.get("isError", False),
                          "status": value.get("status"), "code": value.get("error_code")}), flush=True)
        return content.get("isError", False), value

    def candidate(self, version, stand):
        data = (self.run / f"payload-v{version}.cfe").read_bytes()
        return {"name": "FixturePayload", "cfe_base64": base64.b64encode(data).decode(),
                "sha256": hashlib.sha256(data).hexdigest(), "expected_stand": stand}

    def probe(self):
        self.request("/hs/fixture/bootstrap", b"", "")
        error, inspected = self.call("extension_inspect", {"name": "mcp_tools"}, "inspect-mcp")
        assert not error, inspected
        assert inspected["configuration_name"] == "ExtensionApiFixture", inspected
        assert inspected["applied_in_current_session"], inspected
        assert not inspected["installation_enabled"], inspected
        args = self.candidate(1, inspected["stand_fingerprint"])
        error, validated = self.call("extension_validate", args, "validate-v1")
        assert not error and validated["applicable"], validated
        assert not validated["exists"], validated
        save(self.run / "minimum-result.json", {"inspect": "passed", "validate": "passed", "stand": inspected["stand_fingerprint"]})
        return args, validated

    def install_cycle(self, args, validated):
        def reject(arguments, label, code="validation_failed", user="FixtureOperator", tool="extension_install"):
            error, result = self.call(tool, arguments, label, user)
            assert error and result["error_code"] == code, result
        install = dict(args, confirm=True, expected_previous_sha256="", safe_mode=False, dangerous_actions_protection=False)
        reject({"name": "FixturePayload"}, "negative-role", "role_required", "FixtureDenied", "extension_inspect")
        reject(install, "negative-install-role", "install_role_required", "FixtureProbe")
        reject(dict(install, confirm=False), "negative-confirm")
        reject(dict(install, safe_mode="false"), "negative-setting-string")
        reject(dict(install, dangerous_actions_protection=None), "negative-setting-null")
        reject(dict(args, sha256="0" * 64), "negative-sha256", tool="extension_validate")
        reject(dict(args, expected_stand="0" * 64), "negative-stand", tool="extension_validate")
        reject(dict(args, name="OtherPayload"), "negative-name", tool="extension_validate")
        reject(install, "negative-disabled", "installation_disabled")
        self.request("/hs/fixture/enable", b"")
        reject(install, "negative-file-access", "backup_directory_unavailable")
        self.request("/hs/fixture/file-access", b"")
        # Private VRD disables service-session reuse and bounds idle connections to one second.
        time.sleep(2)
        error, stored = self.call("extension_install", install, "install-v1")
        assert not error and stored["status"] == "stored", stored
        assert stored["artifact_platform_hash"] == validated["artifact_platform_hash"] == stored["stored_platform_hash"], stored
        error, applied = self.call("extension_inspect", {"name": "FixturePayload"}, "applied-v1")
        assert not error and applied["applied_in_current_session"], applied
        assert applied["session_id"] != stored["session_id"], (stored, applied)
        assert applied["session_platform_hash"] == stored["artifact_platform_hash"], applied
        assert applied["safe_mode"] is False and applied["dangerous_actions_protection"] is False, applied
        reject(install, "negative-previous-hash", "install_rejected")
        args2 = self.candidate(2, args["expected_stand"])
        error, validated2 = self.call("extension_validate", args2, "validate-v2")
        assert not error and validated2["applicable"], validated2
        assert validated2["artifact_platform_hash"] != validated["artifact_platform_hash"], validated2
        error, stored2 = self.call("extension_install", dict(args2, confirm=True,
                                  expected_previous_sha256=applied["stored_sha256"], safe_mode=False,
                                  dangerous_actions_protection=False), "install-v2")
        assert not error and stored2["status"] == "stored", stored2
        backup = Path(stored2["backup_path"])
        assert backup.is_file() and sha(backup) == stored2["backup_sha256"] == applied["stored_sha256"], stored2
        shutil.copy2(backup, self.run / "payload-backup-v1.cfe")
        error, applied2 = self.call("extension_inspect", {"name": "FixturePayload"}, "applied-v2")
        assert not error and applied2["applied_in_current_session"], applied2
        assert applied2["session_id"] != stored2["session_id"], (stored2, applied2)
        assert applied2["session_platform_hash"] == stored2["stored_platform_hash"] == validated2["artifact_platform_hash"], applied2
        assert applied2["safe_mode"] is False and applied2["dangerous_actions_protection"] is False, applied2
        for index, safe_mode in enumerate((True, False), 1):
            error, settings_stored = self.call("extension_install", dict(args2, confirm=True,
                expected_previous_sha256=applied2["stored_sha256"], safe_mode=safe_mode,
                dangerous_actions_protection=False), f"settings-only-{index}-stored")
            assert not error and settings_stored["status"] == "stored", settings_stored
            error, settings_applied = self.call("extension_inspect", {"name": "FixturePayload"}, f"settings-only-{index}-applied")
            assert not error and settings_applied["applied_in_current_session"], settings_applied
            assert settings_applied["session_id"] != settings_stored["session_id"], settings_applied
            assert settings_applied["safe_mode"] is safe_mode and settings_applied["session_safe_mode"] is safe_mode, settings_applied
            assert settings_applied["dangerous_actions_protection"] is False and settings_applied["session_dangerous_actions_protection"] is False, settings_applied
            assert settings_applied["session_platform_hash"] == validated2["artifact_platform_hash"], settings_applied
            applied2 = settings_applied
        self.request("/hs/fixture/disable", b"")
        return {"inspect": "passed", "validate": "passed", "install": "passed",
             "update": "passed", "backup": "sha256-verified", "fresh_session_proof": "passed", "negative_gates": 11,
             "settings_only_proof": "passed", "final_safe_mode": False, "final_dangerous_actions_protection": False,
             "execute_code_enabled": False, "foreign_databases_changed": False, "installation_disabled_at_end": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-disposable", action="store_true", required=True)
    parser.add_argument("--platform", type=Path, required=True)
    parser.add_argument("--apache", type=Path, required=True)
    args = parser.parse_args()
    run = ROOT / "build/extension-api/isolated-live" / uuid.uuid4().hex
    run.mkdir(parents=True)
    print(json.dumps({"run": str(run)}), flush=True)
    manifest = source_manifest()
    save(run / "source-manifest.json", manifest)
    shutil.copytree(ROOT / "src/1c_ext", run / "inputs/mcp")
    shutil.copytree(FIXTURE, run / "inputs/fixture")
    shutil.copy2(__file__, run / "inputs/harness.py")
    assert source_manifest() == manifest, "Исходники изменились во время снимка. Новый запуск нужен до любых HTTP-записей."
    prepare(run, args.platform)
    assert source_manifest() == manifest, "Исходники изменились во время сборки; HTTP-пилот не запускается."
    port = publication(run, args.platform, args.apache)
    log = (run / "apache-console.log").open("wb")
    server = subprocess.Popen([str(args.apache), "-f", str(run / "httpd.conf")], stdout=log, stderr=subprocess.STDOUT, **hidden())
    save(run / "listener.json", {"pid": server.pid, "port": port, "host": "127.0.0.1", "run": str(run)})
    result = None
    try:
        for _ in range(40):
            if server.poll() is not None:
                raise RuntimeError("Собственный Apache завершился: см. apache-console.log")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.25)
        pilot = Pilot(run, port)
        candidate, validated = pilot.probe()
        result = pilot.install_cycle(candidate, validated)
    finally:
        # Windows -k stop targets a registered service even with a private config.
        # Stop only the process tree created by THIS Popen, never a service/name match.
        if server.poll() is None:
            subprocess.run(["taskkill", "/PID", str(server.pid), "/T", "/F"],
                           stdout=log, stderr=subprocess.STDOUT, timeout=20, **hidden())
            server.wait(timeout=30)
        log.close()
        with socket.socket() as probe:
            probe.settimeout(2)
            port_closed = probe.connect_ex(("127.0.0.1", port)) != 0
        save(run / "cleanup.json", {"own_parent_pid": server.pid, "parent_exited": server.poll() is not None,
                                    "port": port, "listener_closed": port_closed, "process_name_kill": False})
        if not port_closed:
            raise RuntimeError("Закрытие собственного listener не подтверждено; чужие процессы не завершаем.")
    assert source_manifest() == manifest, "Исходники изменились во время пилота; итог не сертифицирован."
    if result is not None:
        result.update(source_snapshot_verified=True, listener_closed=True)
        save(run / "result.json", result)
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
