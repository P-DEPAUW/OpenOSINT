"""Tests for keyless local entry, display compactness and MCP dispatch."""
import asyncio
import json
import sys
from types import SimpleNamespace

from openosint import local_menu as menu


def test_keyless_menu_has_ten_supported_categories():
    keys = [key for key, _ in menu.MAIN_ITEMS]
    assert keys == ["naam", "username", "email", "phone", "domain", "tools", "all", "reports", "settings", "quit"]


def test_theme_is_dark_and_selected_is_distinct():
    for name in menu.PALETTES:
        prefs = {"palette": name, "emoji": False}
        style = menu._style(prefs)
        assert style is not None
        parts = menu._menu_text(menu.MAIN_ITEMS, 0, prefs, 80)
        assert any("selected" in style_name for style_name, _ in parts)
        assert any("WAT WIL JE ONDERZOEKEN" in text for _, text in parts)
        assert any("Afsluiten" in text for _, text in parts)


def test_preview_never_mutates_the_original():
    content = "\n".join(f"evidence line {i}" for i in range(30))
    displayed, hidden = menu._preview(content)
    assert hidden == 16
    assert len(displayed.splitlines()) == 14
    assert menu._preview(content, compact=False) == (content, 0)
    assert content.endswith("evidence line 29")


def test_photo_is_manual_and_never_uploads(tmp_path):
    file = tmp_path / "test.png"
    file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\0" * 32)
    result, error = asyncio.run(menu._run_tool("image", str(file)))
    assert not error
    assert "geen reverse-imagezoekopdracht" in result
    assert "Google Lens" in result


def test_mcp_handler_reused_without_new_backend(monkeypatch):
    calls = []

    async def fake(name, arguments):
        calls.append((name, arguments))
        return SimpleNamespace(content=[SimpleNamespace(text="SOURCE_RESULT")], isError=False)

    monkeypatch.setattr(menu, "call_tool", fake)
    answer, error = asyncio.run(menu._run_tool("search_certificates", "example.com"))
    assert (answer, error) == ("SOURCE_RESULT", False)
    assert calls == [("search_certificates", {"domain": "example.com"})]


def test_settings_read_existing_config(monkeypatch):
    monkeypatch.setattr(menu, "read_config", lambda: {"OPENOSINT_TERMINAL_PALETTE": "lavendel", "OPENOSINT_TERMINAL_EMOJI": "0"})
    assert menu._preferences() == {"palette": "lavendel", "emoji": False}


def test_cli_no_key_uses_local_menu(monkeypatch):
    from openosint import cli

    calls = []

    async def fake_menu():
        calls.append("menu")

    monkeypatch.setattr(menu, "run_local_menu", fake_menu)
    monkeypatch.setattr(sys, "argv", ["openosint"])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    asyncio.run(cli._async_main())
    assert calls == ["menu"]


def test_lens_one_active_call_then_restores_policy(monkeypatch):
    import os

    from openosint.tool_policy import ENV_ALLOW_ACTIVE
    calls = []

    async def fake(name, arguments):
        calls.append((name, arguments, os.environ.get(ENV_ALLOW_ACTIVE)))
        payload = {"source": "SerpApi Google Lens", "matches": [{"title": "Public photo", "link": "https://example.org/photo"}]}
        return SimpleNamespace(content=[SimpleNamespace(text=json.dumps(payload))], isError=False)

    monkeypatch.setattr(menu, "call_tool", fake)
    monkeypatch.delenv(ENV_ALLOW_ACTIVE, raising=False)
    result, error = asyncio.run(menu._run_tool("search_lens", "https://example.org/cat.jpg"))
    assert not error
    assert calls == [("search_lens", {"image_url": "https://example.org/cat.jpg"}, "1")]
    assert ENV_ALLOW_ACTIVE not in os.environ
    assert "Public photo" in menu._lens_brief(result)


def test_lens_invalid_provider_response_is_error(monkeypatch):
    async def failed(name, arguments):
        return SimpleNamespace(content=[SimpleNamespace(text="Provider HTTP 401")], isError=False)

    monkeypatch.setattr(menu, "call_tool", failed)
    response, error = asyncio.run(menu._run_tool("search_lens", "https://example.org/cat.jpg"))
    assert error
    assert response == "Provider HTTP 401"
