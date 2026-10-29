"""Search categories in Owen's existing terminal chat do not call AI/tools."""
from io import StringIO

from rich.console import Console

from openosint import repl


def test_search_list_is_english_and_not_a_tool_list(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(repl, "console", Console(file=output, width=110))
    repl._print_search_list()
    text = output.getvalue()
    for label in (
        "SEARCH LIST", "Name", "Username", "Email address", "Phone number",
        "IP address", "Domain", "Photo / image", "Company", "Location",
        "File / hash", "No search started",
    ):
        assert label in text
    assert "search_username" not in text
    assert "zoeklijst" not in text.lower()


def test_help_mentions_searchlist(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(repl, "console", Console(file=output, width=110))
    repl._print_help()
    assert "searchlist" in output.getvalue()


def test_searchlist_dispatch_is_before_any_ai_investigation():
    import inspect
    src = inspect.getsource(repl.OpenOSINTRepl.run)
    assert '"searchlist"' in src
    assert src.index('if user_input.lower() in ("searchlist"') < src.index("await self._run_investigation(user_input)")
