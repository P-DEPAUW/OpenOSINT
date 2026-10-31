"""The 12 actual Debian OSINT executables are selectable, never guessed."""
import asyncio
from unittest.mock import patch

import pytest

from openosint.mcp_server import _all_tools, call_tool
from openosint.tool_policy import ENV_ALLOW_ACTIVE
from openosint.tools import debian_collection as dc

EXPECTED = {
    "sherlock", "maigret", "blackbird", "social-analyzer", "holehe",
    "ghunt", "phoneinfoga", "ignorant", "theHarvester", "subfinder",
    "whois", "spiderfoot",
}


def test_twelve_real_tools_are_registered():
    assert set(dc.DEBIAN_TOOLS) == EXPECTED
    assert len(dc.DEBIAN_TOOLS) == 12


@pytest.mark.parametrize(
    ("tool", "value"),
    [("sherlock", "dpmadness"), ("maigret", "dpmadness"),
     ("blackbird", "dpmadness"), ("social-analyzer", "dpmadness"),
     ("holehe", "name@example.org"), ("ghunt", "name@example.org"),
     ("phoneinfoga", "+32470000000"), ("ignorant", "+32470000000"),
     ("theHarvester", "example.org"), ("subfinder", "example.org"),
     ("whois", "example.org"), ("spiderfoot", "example.org")],
)
def test_each_tool_has_safe_arguments(tool, value):
    args = dc.arguments(tool, value)
    assert args and isinstance(args, list)
    assert all(isinstance(a, str) for a in args)


@pytest.mark.parametrize("bad", ["; rm -rf /", "-x", "bad\ninput", "../.."])
def test_rejects_shell_injection_input(bad):
    with pytest.raises(ValueError):
        dc.validate("sherlock", bad)


def test_debian_mcp_tool_list_has_both_access_modes():
    names = [t.name for t in _all_tools()]
    assert "list_debian_osint" in names
    assert "search_debian_osint" in names


def test_catalog_is_read_only_and_lists_all_twelve(monkeypatch):
    monkeypatch.setattr(dc, "vm_status", lambda: "stopped")
    text = dc.catalog()
    assert all(name in text for name in EXPECTED)
    assert "VM: stopped" in text


def test_tool_policy_denies_active_search_by_default(monkeypatch):
    monkeypatch.delenv(ENV_ALLOW_ACTIVE, raising=False)
    result = asyncio.run(
        call_tool("search_debian_osint", {"tool": "maigret", "target": "testuser"})
    )
    assert result.isError


def test_mcp_catalog_works_without_debian(monkeypatch):
    monkeypatch.setattr(dc, "vm_status", lambda: "T9 disconnected")
    result = asyncio.run(call_tool("list_debian_osint", {}))
    assert not result.isError
    assert "T9 disconnected" in result.content[0].text


def test_no_vm_start_for_catalog(monkeypatch):
    monkeypatch.setattr(dc.os.path, "ismount", lambda path: False)
    with patch.object(dc.subprocess, "run") as runner:
        assert "T9 disconnected" in dc.catalog()
        runner.assert_not_called()


def test_tools_menu_exposes_the_complete_collection():
    from openosint.local_menu import TOOL_ITEMS

    assert ("debian12", "12 bestaande Debian OSINT-tools") in TOOL_ITEMS


def test_ai_sees_search_tool_only_with_active_authorization(monkeypatch):
    from openosint.mcp_server import list_tools

    monkeypatch.delenv(ENV_ALLOW_ACTIVE, raising=False)
    passive = {t.name for t in asyncio.run(list_tools())}
    assert "list_debian_osint" in passive
    assert "search_debian_osint" not in passive
    monkeypatch.setenv(ENV_ALLOW_ACTIVE, "1")
    active = {t.name for t in asyncio.run(list_tools())}
    assert "search_debian_osint" in active


def test_terminal_can_call_any_selected_debian_tool_without_duplication(monkeypatch):
    from types import SimpleNamespace

    from openosint import local_menu

    called = []

    async def fake_call(name, args):
        called.append((name, args))
        return SimpleNamespace(content=[SimpleNamespace(text="source result")], isError=False)

    monkeypatch.setattr(local_menu, "call_tool", fake_call)
    monkeypatch.delenv(ENV_ALLOW_ACTIVE, raising=False)
    response, failed = asyncio.run(
        local_menu._run_tool("search_debian_osint", "example.org", legacy_tool="spiderfoot")
    )
    assert response == "source result" and not failed
    assert called == [("search_debian_osint", {"tool": "spiderfoot", "target": "example.org"})]
    assert ENV_ALLOW_ACTIVE not in local_menu.os.environ


def test_no_guest_returns_actual_error_to_agent(monkeypatch):
    monkeypatch.setenv(ENV_ALLOW_ACTIVE, "1")
    monkeypatch.setattr(dc, "vm_status", lambda: "T9 disconnected")
    result = asyncio.run(
        call_tool("search_debian_osint", {"tool": "maigret", "target": "publicuser"})
    )
    assert result.isError is True
    assert "T9 disconnected" in result.content[0].text
