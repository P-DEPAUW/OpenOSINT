"""Keyless, keyboard-driven entry to the existing registered OpenOSINT tools.

This is not another OSINT backend: dispatch goes through the same MCP tool
handlers/policies used by the agent and the ordinary command line.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

from prompt_toolkit import PromptSession
from prompt_toolkit.application import Application
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import FormattedTextControl, Layout, Window
from prompt_toolkit.styles import Style
from rich import box
from rich.console import Console
from rich.panel import Panel

from openosint.config_store import read_config, write_config
from openosint.image_search import prepare_image_search
from openosint.mcp_server import call_tool, list_tools
from openosint.tool_policy import ENV_ALLOW_ACTIVE

# Semantic colors: keep all themes OLED black with a dark selected row.
PALETTES = {
    "paars": {"title": "#A78BFA", "accent": "#79BAC8", "body": "#B6A7C8", "muted": "#9A9FB4"},
    "lavendel": {"title": "#B8A7D5", "accent": "#A3B9CB", "body": "#C1B2D3", "muted": "#A1A2B7"},
    "cyaan": {"title": "#79BAC8", "accent": "#A78BFA", "body": "#ACCCD1", "muted": "#9AAEB6"},
}
MAIN_ITEMS = (
    ("naam", "Naam"), ("username", "Gebruikersnaam"), ("email", "E-mailadres"),
    ("phone", "Telefoonnummer"), ("domain", "Domein"), ("tools", "Tools kiezen"),
    ("all", "Alle tools als lijst"), ("reports", "Rapporten bekijken"),
    ("settings", "Kleuren · emoji's · opties"), ("quit", "Afsluiten"),
)
# Only pre-existing, registered handlers. Passive mode is always checked by MCP.
TOOL_ITEMS = (
    ("image", "Foto: zoekmogelijkheden"),
    ("search_lens", "Google Lens: echte matches (openbare foto-URL)"),
    ("search_certificates", "Certificaten / subdomeinen"),
    ("search_archive", "Webarchief"),
    ("search_github", "GitHub-profiel"),
    ("search_dns", "DNS"), ("search_rdap", "RDAP"),
    ("search_ip", "IP-informatie"), ("search_greynoise", "GreyNoise IP"),
    ("file_metadata", "Metadata uit lokale foto"),
    ("generate_dorks", "Zoeklinks voorbereiden"),
    ("back", "Terug"),
)
INPUT_KEYS = {
    "search_certificates": "domain", "search_archive": "domain",
    "search_github": "query", "search_dns": "domain", "search_rdap": "domain",
    "search_ip": "ip", "search_greynoise": "ip", "file_metadata": "path",
    "generate_dorks": "target",
    "search_lens": "image_url",
}


def _preferences() -> dict[str, Any]:
    config = read_config()
    palette = config.get("OPENOSINT_TERMINAL_PALETTE", "paars")
    return {"palette": palette if palette in PALETTES else "paars",
            "emoji": config.get("OPENOSINT_TERMINAL_EMOJI", "1") != "0"}


def _style(preferences: dict) -> Style:
    colors = PALETTES[preferences["palette"]]
    return Style.from_dict({
        "": "bg:#000000 " + colors["body"],
        "title": colors["title"] + " bold",
        "accent": colors["accent"],
        "border": "#79658E", "muted": colors["muted"],
        "selected": "bg:#352347 #C8B5DE bold",
    })


def _menu_text(items: tuple, selected: int, preferences: dict, width: int) -> FormattedText:
    width = max(30, min(width - 6, 54))
    title = ("🔎 " if preferences["emoji"] else "") + "WAT WIL JE ONDERZOEKEN?"
    header = title.ljust(width - 2)
    title_art = "   ___  ____ ___ _   _ _____\n  / _ \\/ ___|_ _| \\ | |_   _|\n | | | \\___ \\| ||  \\| | | |\n | |_| | ___) | || |\\  | | |\n  \\___/ |____/___|_| \\_| |_|\n" if width >= 43 else "  O S I N T\n"
    lines: list[tuple[str, str]] = [("class:title", title_art), ("class:border", "╭" + "─" * width + "╮\n"),
                                     ("class:accent", "│ " + header + " │\n"),
                                     ("class:border", "├" + "─" * width + "┤\n")]
    for i, (_, label) in enumerate(items):
        chosen = i == selected
        content = (" › " if chosen else "   ") + label
        content = content[:width].ljust(width)
        lines += [("class:border", "│"), ("class:selected" if chosen else "", content), ("class:border", "│\n")]
    lines.extend([("class:border", "╰" + "─" * width + "╯\n"),
                  ("class:muted", "↑↓ Kiezen  Enter Openen  Esc Terug\n")])
    return FormattedText(lines)


async def _choose(items: tuple, preferences: dict) -> str | None:
    selected = 0
    keybinds = KeyBindings()

    @keybinds.add("up")
    def _up(event):
        nonlocal selected
        selected = (selected - 1) % len(items)
        event.app.invalidate()

    @keybinds.add("down")
    def _down(event):
        nonlocal selected
        selected = (selected + 1) % len(items)
        event.app.invalidate()

    @keybinds.add("enter")
    def _enter(event):
        event.app.exit(result=items[selected][0])

    @keybinds.add("escape")
    @keybinds.add("c-c")
    def _back(event):
        event.app.exit(result=None)

    screen = FormattedTextControl(lambda: _menu_text(items, selected, preferences, shutil.get_terminal_size((80, 24)).columns), focusable=True)
    app: Application[str | None] = Application(
        layout=Layout(Window(content=screen, always_hide_cursor=True)),
        key_bindings=keybinds, style=_style(preferences), full_screen=False,
        erase_when_done=True,
    )
    return await app.run_async()


def _preview(text: str, compact: bool = True, limit: int = 14) -> tuple[str, int]:
    """Display-only preview. Never alter the source evidence, saved report or API result."""
    if not compact:
        return text, 0
    lines = text.splitlines()
    if len(lines) <= limit and len(text) <= 2000:
        return text, 0
    shown = lines[:limit]
    remainder = len(lines) - len(shown)
    if not remainder and len(text) > 2000:
        return text[:1900] + "\n… uitvoer ingekort; volledig rapport beschikbaar.", 1
    return "\n".join(shown), remainder


def _render(console: Console, text: str, *, compact: bool = True, error: bool = False) -> None:
    visible, omitted = _preview(text, compact)
    color = "#C68F99" if error else "#79658E"
    console.print(Panel(visible or "Geen uitvoer ontvangen.", border_style=color, style="#B6A7C8", padding=(0, 1), box=box.ROUNDED))
    if omitted:
        console.print(f"[{ '#C2A674' }]Nog {omitted} regels verborgen; kies 'Volledig' of 'Bewaar rapport'.[/]")


async def _prompt_value(prompt: PromptSession, label: str) -> str | None:
    try:
        value = (await prompt.prompt_async(f"{label} (Ctrl-C = terug): ")).strip()
    except (KeyboardInterrupt, EOFError):
        return None
    return value or None


async def _run_tool(name: str, value: str) -> tuple[str, bool]:
    if name == "image":
        try:
            result = prepare_image_search(value)
        except (ValueError, OSError) as exc:
            return str(exc), True
        providers = "\n".join(f"{p['name']}: {p['url']}" for p in result["providers"])
        return ("Foto gecontroleerd. Zoekpagina's beschikbaar (nog geen reverse-imagezoekopdracht uitgevoerd):\n" + providers), False
    if name not in INPUT_KEYS:
        return "Onbekende tool; niets uitgevoerd.", True
    if name == "search_lens":
        # This is reached only after the user explicitly confirms sending the
        # public image URL. Turn on active policy for this ONE tool invocation.
        old_value = os.environ.get(ENV_ALLOW_ACTIVE)
        os.environ[ENV_ALLOW_ACTIVE] = "1"
        try:
            answer = await call_tool(name, {INPUT_KEYS[name]: value})
        finally:
            if old_value is None:
                os.environ.pop(ENV_ALLOW_ACTIVE, None)
            else:
                os.environ[ENV_ALLOW_ACTIVE] = old_value
    else:
        answer = await call_tool(name, {INPUT_KEYS[name]: value})
    chunks = [getattr(c, "text", "") for c in answer.content]
    raw = "\n".join(chunks)
    if name == "search_lens" and not answer.isError:
        # Some providers return an HTTP/JSON error as plain tool text.
        try:
            data = json.loads(raw)
        except (TypeError, ValueError):
            return raw, True
        return raw, not (isinstance(data, dict) and data.get("source") == "SerpApi Google Lens" and isinstance(data.get("matches"), list))
    return raw, bool(answer.isError)


def _lens_brief(raw: str) -> str:
    """Present a short readable result, leaving raw evidence untouched."""
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return raw
    if not isinstance(data, dict) or data.get("source") != "SerpApi Google Lens":
        return raw
    matches = data.get("matches", [])
    if not isinstance(matches, list):
        return raw
    lines = [f"Google Lens: {len(matches)} visuele matches (geen identiteitsbewijs)."]
    for i, entry in enumerate(matches[:5], start=1):
        if not isinstance(entry, dict):
            continue
        title = str(entry.get("title", "Geen titel")).strip()[:90]
        source = str(entry.get("source", "")).strip()[:60]
        url = str(entry.get("link", "")).strip()[:300]
        lines.append(f"{i}. {title}" + (f" · {source}" if source else ""))
        if url.startswith(("https://", "http://")):
            lines.append(f"   {url}")
    if len(matches) > 5:
        lines.append(f"Nog {len(matches) - 5} matches via 'Volledig resultaat'.")
    return "\n".join(lines)


async def run_local_menu() -> None:
    prefs = _preferences()
    console = Console(highlight=False, theme=None)
    prompt = PromptSession()
    last_full = ""
    while True:
        action = await _choose(MAIN_ITEMS, prefs)
        if action in (None, "quit"):
            console.print("[#9A9FB4]OpenOSINT afgesloten.[/]")
            return
        if action == "settings":
            opts = (("paars", "Paars · cyaan"), ("lavendel", "Lavendel"), ("cyaan", "Zacht cyaan"), ("emoji", "Emoji's aan/uit"), ("back", "Terug"))
            choice = await _choose(opts, prefs)
            if choice in PALETTES:
                prefs["palette"] = choice
                write_config({"OPENOSINT_TERMINAL_PALETTE": choice})
            elif choice == "emoji":
                prefs["emoji"] = not prefs["emoji"]
                write_config({"OPENOSINT_TERMINAL_EMOJI": "1" if prefs["emoji"] else "0"})
            continue
        if action == "all":
            tools = await list_tools()
            console.print(f"[#79BAC8]Beschikbare tools: {len(tools)} (actieve tools verborgen)[/]")
            for t in tools:
                console.print(f"[#B6A7C8]• {t.name}[/]")
            await _prompt_value(prompt, "Enter om terug te gaan")
            continue
        if action == "reports":
            records = sorted(Path("reports").glob("*_report.md"), reverse=True)[:10]
            if records:
                for record in records:
                    console.print(f"[#B6A7C8]{record}[/]")
            else:
                console.print("[#C2A674]Nog geen rapporten in deze map.[/]")
            await _prompt_value(prompt, "Enter om terug te gaan")
            continue
        if action == "tools":
            chosen = await _choose(TOOL_ITEMS, prefs)
            if chosen in (None, "back"):
                continue
            name = chosen
        elif action == "domain":
            chosen = await _choose((("search_certificates", "Certificaten"), ("search_archive", "Webarchief"), ("search_dns", "DNS"), ("search_rdap", "RDAP"), ("back", "Terug")), prefs)
            if chosen in (None, "back"):
                continue
            name = chosen
        elif action == "username":
            name = "search_github"
        elif action in ("email", "phone", "naam"):
            name = "generate_dorks"
            console.print("[#C2A674]Deze route bereidt alleen zoeklinks voor; geen accounts of personen zijn geverifieerd.[/]")
        else:
            continue
        label = ("Publieke HTTPS-foto-URL" if name == "search_lens" else
                 "Foto (pad of HTTPS-link)" if name == "image" else
                 "Bestand" if name == "file_metadata" else "Onderzoekwaarde")
        value = await _prompt_value(prompt, label)
        if value is None:
            continue
        if name == "search_lens":
            console.print("[#C2A674]SerpApi ontvangt deze OPENBARE foto-URL. Lokale foto's worden niet geüpload.[/]")
            agreed = await _choose((("go", "Verstuur URL en zoek met SerpApi"),
                                     ("back", "Terug zonder zoeken")), prefs)
            if agreed != "go":
                continue
        console.print("[#9A9FB4]Onderzoek gestart; status volgt uit de echte bron.[/]")
        full, failure = await _run_tool(name, value)
        last_full = f"Tool: {name}\nOnderzocht: {value}\n\n{full}"
        visible = _lens_brief(full) if name == "search_lens" and not failure else full
        _render(console, visible, error=failure)
        while True:
            choice = await _choose((("back", "Terug"), ("full", "Volledig resultaat"), ("save", "Bewaar rapport")), prefs)
            if choice in (None, "back"):
                break
            if choice == "full":
                _render(console, full, compact=False, error=failure)
            elif choice == "save":
                # Reuse the established report mechanism: never save a shortened version.
                from openosint.repl import _save_report
                output = _save_report(last_full)
                console.print(f"[#8EB895]Volledig rapport opgeslagen: {output}[/]")
