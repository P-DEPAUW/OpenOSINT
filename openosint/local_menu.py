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
from openosint.tools.debian_collection import DEBIAN_TOOLS

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
    ("search_username", "Sherlock: gebruikersnamen (Mac/Debian)"),
    ("search_email", "Holehe: e-mailaccounts (Debian)"),
    ("search_phone", "PhoneInfoga: telefoonnummers (Mac/Debian)"),
    ("search_domain", "Sublist3r: domeinen (Debian)"),
    ("debian12", "12 bestaande Debian OSINT-tools"),
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
    "search_username": "username", "search_email": "email",
    "search_phone": "phone", "search_domain": "domain",
    "search_debian_osint": "target",
}
ACTIVE_MENU_TOOLS = frozenset({
    "search_lens", "search_username", "search_email", "search_phone", "search_domain",
    "search_debian_osint",
})


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


async def _run_tool(
    name: str, value: str, legacy_tool: str | None = None
) -> tuple[str, bool]:
    if name == "image":
        try:
            result = prepare_image_search(value)
        except (ValueError, OSError) as exc:
            return str(exc), True
        providers = "\n".join(f"{p['name']}: {p['url']}" for p in result["providers"])
        return ("Foto gecontroleerd. Zoekpagina's beschikbaar (nog geen reverse-imagezoekopdracht uitgevoerd):\n" + providers), False
    if name not in INPUT_KEYS:
        return "Onbekende tool; niets uitgevoerd.", True
    if name in ACTIVE_MENU_TOOLS:
        # Explicitly chosen and confirmed from the local menu. Allow only
        # this invocation to use active/noisy tools, then restore policy.
        old_value = os.environ.get(ENV_ALLOW_ACTIVE)
        os.environ[ENV_ALLOW_ACTIVE] = "1"
        try:
            arguments = {INPUT_KEYS[name]: value}
            if name == "search_debian_osint":
                if legacy_tool not in DEBIAN_TOOLS:
                    return "Invalid Debian tool selection; nothing executed.", True
                arguments["tool"] = legacy_tool
            answer = await call_tool(name, arguments)
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
        legacy_tool = None
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
            if chosen == "debian12":
                legacy_tool = await _choose(
                    tuple(
                        (tool, f"{tool} · {spec.kind}")
                        for tool, spec in DEBIAN_TOOLS.items()
                    ) + (("back", "Terug"),),
                    prefs,
                )
                if legacy_tool in (None, "back"):
                    continue
                name = "search_debian_osint"
            else:
                name = chosen
        elif action == "domain":
            chosen = await _choose((("search_certificates", "Certificaten"), ("search_archive", "Webarchief"), ("search_dns", "DNS"), ("search_rdap", "RDAP"), ("search_domain", "Sublist3r (Debian)"), ("back", "Terug")), prefs)
            if chosen in (None, "back"):
                continue
            name = chosen
        elif action == "username":
            chosen = await _choose((("search_github", "GitHub (passief)"),
                                    ("search_username", "Sherlock (actief; Mac/Debian)"),
                                    ("back", "Terug")), prefs)
            if chosen in (None, "back"):
                continue
            name = chosen
        elif action == "email":
            chosen = await _choose((("generate_dorks", "Zoeklinks (passief)"),
                                    ("search_email", "Holehe (actief; Debian)"),
                                    ("back", "Terug")), prefs)
            if chosen in (None, "back"):
                continue
            name = chosen
        elif action == "phone":
            chosen = await _choose((("generate_dorks", "Zoeklinks (passief)"),
                                    ("search_phone", "PhoneInfoga (actief; Mac/Debian)"),
                                    ("back", "Terug")), prefs)
            if chosen in (None, "back"):
                continue
            name = chosen
        elif action == "naam":
            name = "generate_dorks"
            console.print("[#C2A674]Deze route bereidt alleen zoeklinks voor; geen identiteit geverifieerd.[/]")
        else:
            continue
        label = ("Publieke HTTPS-foto-URL" if name == "search_lens" else
                 "Foto (pad of HTTPS-link)" if name == "image" else
                 "Bestand" if name == "file_metadata" else "Onderzoekwaarde")
        value = await _prompt_value(prompt, label)
        if value is None:
            continue
        if name in ACTIVE_MENU_TOOLS:
            if name == "search_lens":
                warning = "SerpApi ontvangt deze OPENBARE foto-URL. Lokale foto's worden niet geüpload."
                proceed = "Verstuur URL en zoek met SerpApi"
            else:
                warning = "Deze tool kan diensten of het doel benaderen en veel verzoeken sturen. Alleen bevoegd onderzoek."
                proceed = "Voer deze zoekopdracht uit"
            console.print(f"[#C2A674]{warning}[/]")
            agreed = await _choose((("go", proceed), ("back", "Terug zonder zoeken")), prefs)
            if agreed != "go":
                continue
        console.print("[#9A9FB4]Onderzoek gestart; status volgt uit de echte bron.[/]")
        full, failure = await _run_tool(name, value, legacy_tool=legacy_tool)
        last_full = f"Tool: {legacy_tool or name}\nOnderzocht: {value}\n\n{full}"
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
