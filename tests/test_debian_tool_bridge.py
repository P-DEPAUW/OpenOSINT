"""Guest extension must never invent tools or depend on a dead Debian IP."""
import importlib.util
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/debian_tool_bridge.py"
spec = importlib.util.spec_from_file_location("debian_tool_bridge", SCRIPT)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


def test_allowlist_is_only_existing_tools():
    assert set(bridge.GUEST_TOOLS) == {"sherlock", "holehe", "phoneinfoga", "sublist3r"}
    assert bridge.GUEST_TOOLS["phoneinfoga"] is None


def test_guest_missing_does_not_start_vm():
    with patch.object(bridge.os.path, "ismount", return_value=False):
        with patch.object(bridge.subprocess, "run") as run:
            assert bridge.guest_available() is False
            run.assert_not_called()


def test_guest_exec_uses_array_not_shell(monkeypatch):
    monkeypatch.setattr(bridge.sys, "argv", ["sherlock", "example_user", "--help"])
    monkeypatch.setattr(bridge, "guest_available", lambda: True)
    with patch.object(bridge.os, "execv", side_effect=RuntimeError("exec captured")) as run:
        try:
            bridge.main()
        except RuntimeError:
            pass
        cmd = run.call_args.args[1]
        assert cmd[1:5] == ["exec", "Debian VM", "/usr/bin/sherlock", "example_user"]
        assert "--help" in cmd


def test_guest_off_uses_real_local_binary(monkeypatch):
    monkeypatch.setattr(bridge.sys, "argv", ["phoneinfoga", "--help"])
    monkeypatch.setattr(bridge, "guest_available", lambda: False)
    monkeypatch.setattr(bridge, "_native_path", lambda t: "/opt/homebrew/bin/phoneinfoga")
    with patch.object(bridge.os, "execv", side_effect=RuntimeError("exec captured")) as run:
        try:
            bridge.main()
        except RuntimeError:
            pass
        assert run.call_args.args[1] == ["/opt/homebrew/bin/phoneinfoga", "--help"]


def test_stopped_vm_does_not_auto_start_without_explicit_opt_in(monkeypatch):
    monkeypatch.setattr(bridge.os.path, "ismount", lambda _: True)
    monkeypatch.setattr(bridge.Path, "exists", lambda _: True)
    monkeypatch.delenv("OPENOSINT_AUTOSTART_DEBIAN", raising=False)
    with patch.object(bridge.subprocess, "run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = "VM Debian VM exist stopped"
        assert bridge.guest_available() is False
        assert run.call_count == 1


def test_stopped_vm_starts_lazily_when_opted_in(monkeypatch):
    monkeypatch.setattr(bridge.os.path, "ismount", lambda _: True)
    monkeypatch.setattr(bridge.Path, "exists", lambda _: True)
    monkeypatch.setenv("OPENOSINT_AUTOSTART_DEBIAN", "1")
    with patch.object(bridge.subprocess, "run") as run:
        from types import SimpleNamespace

        run.side_effect = [
            SimpleNamespace(returncode=0, stdout="VM Debian VM exist stopped"),
            SimpleNamespace(returncode=0, stdout="The VM has been successfully started."),
        ]
        assert bridge.guest_available() is True
        assert run.call_args.args[0][1:] == ["start", "Debian VM"]
