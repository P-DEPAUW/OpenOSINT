"""Twelve existing Debian OSINT executables via the authorized Parallels VM.

No duplicate tools, no guest-wide scans and no new server. This catalog is
read-only; executing a target lookup requires an active-policy-enabled call.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import NamedTuple


class ToolSpec(NamedTuple):
    kind: str
    executable: str


# Ten actual Debian menu binaries + the already installed SpiderFoot and
# Social Analyzer. The menu's 'websearch' is a built-in, not a 13th binary.
DEBIAN_TOOLS: dict[str, ToolSpec] = {
    "sherlock": ToolSpec("username", "/usr/local/bin/sherlock"),
    "maigret": ToolSpec("username", "/usr/local/bin/maigret"),
    "blackbird": ToolSpec("username", "/usr/local/bin/blackbird"),
    "social-analyzer": ToolSpec("username", "/usr/local/bin/social-analyzer"),
    "holehe": ToolSpec("email", "/usr/local/bin/holehe"),
    "ghunt": ToolSpec("email", "/usr/local/bin/ghunt"),
    "phoneinfoga": ToolSpec("phone", "/usr/local/bin/phoneinfoga"),
    "ignorant": ToolSpec("phone", "/usr/local/bin/ignorant"),
    "theHarvester": ToolSpec("domain", "/usr/local/bin/theHarvester"),
    "subfinder": ToolSpec("domain", "/usr/local/bin/subfinder"),
    "whois": ToolSpec("domain", "/usr/bin/whois"),
    "spiderfoot": ToolSpec("domain", "/usr/local/bin/spiderfoot"),
}

VM = "Debian VM"
GUEST_PATH = "/usr/local/bin:/usr/bin:/bin"
USERNAME = re.compile(r"[a-zA-Z0-9_.-]{1,64}\Z")
EMAIL = re.compile(r"[^@\s]{1,64}@[^@\s]{1,190}\.[a-zA-Z]{2,24}\Z")
DOMAIN = re.compile(r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
PHONE = re.compile(r"\+[1-9][0-9]{6,14}\Z")


def validate(tool: str, target: str) -> str:
    if tool not in DEBIAN_TOOLS:
        raise ValueError("Unknown Debian OSINT tool; consult list_debian_osint.")
    if not isinstance(target, str):
        raise ValueError("OSINT target must be a string.")
    value = target.strip()
    if value.startswith("-"):
        raise ValueError("OSINT targets cannot begin with an option flag.")
    pattern = {
        "username": USERNAME,
        "email": EMAIL,
        "phone": PHONE,
        "domain": DOMAIN,
    }[DEBIAN_TOOLS[tool].kind]
    if not pattern.fullmatch(value):
        raise ValueError(f"Invalid {DEBIAN_TOOLS[tool].kind} input for {tool}.")
    return value


def arguments(tool: str, value: str) -> list[str]:
    value = validate(tool, value)
    cmds = {
        "sherlock": [value, "--print-found", "--timeout", "3"],
        "maigret": [value, "--timeout", "6", "--no-recursion", "--no-progressbar"],
        "blackbird": ["-u", value, "--no-update"],
        "social-analyzer": [
            "--username", value, "--mode", "fast", "--output", "json", "--top", "20"
        ],
        "holehe": [value],
        "ghunt": ["email", value],
        "phoneinfoga": ["scan", "-n", value],
        "theHarvester": ["-d", value, "-b", "crtsh"],
        "subfinder": ["-d", value],
        "whois": [value],
        "spiderfoot": ["-s", value, "-u", "passive", "-o", "json", "-max-threads", "2"],
    }
    if tool == "ignorant":
        if not value.startswith("+32"):
            raise ValueError("Ignorant currently supports only Belgian +32 numbers.")
        return ["+32", value[3:]]
    return cmds[tool]


def ctl() -> str | None:
    return shutil.which("prlctl") or (
        "/usr/local/bin/prlctl" if Path("/usr/local/bin/prlctl").is_file() else None
    )


def vm_status() -> str:
    if not os.path.ismount("/Volumes/T9"):
        return "T9 disconnected"
    if not Path("/Volumes/T9/VMs/Debian").exists():
        return "Debian VM disk not found on T9"
    command = ctl()
    if not command:
        return "Parallels CLI not available"
    try:
        status = subprocess.run(
            [command, "status", VM], capture_output=True, text=True, timeout=7, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return "Parallels status unavailable"
    if status.returncode:
        return "Parallels Debian status failed"
    return "running" if "exist running" in status.stdout else "stopped"


def catalog() -> str:
    status = vm_status()
    lines = [f"Debian OSINT: 12 configured tool entries; VM: {status}."]
    for name, spec in DEBIAN_TOOLS.items():
        lines.append(f"- {name} | {spec.kind} | {spec.executable}")
    lines.append(
        "Availability is not proof of a successful network lookup. "
        "Live probes require Debian DNS/network access and active-mode permission."
    )
    return "\n".join(lines)


def _execute(tool: str, target: str) -> str:
    value = validate(tool, target)
    status = vm_status()
    if status == "stopped" and os.environ.get("OPENOSINT_AUTOSTART_DEBIAN") == "1":
        started = subprocess.run(
            [ctl(), "start", VM], capture_output=True, text=True, timeout=70, check=False
        )
        if started.returncode:
            return f"{tool}: Debian VM could not start (exit {started.returncode})."
        status = vm_status()
    if status != "running":
        return f"{tool}: Debian unavailable ({status}). Mac OSINT remains available."
    spec = DEBIAN_TOOLS[tool]
    check = subprocess.run(
        [ctl(), "exec", VM, "/usr/bin/test", "-x", spec.executable],
        capture_output=True, text=True, timeout=12, check=False,
    )
    if check.returncode:
        return f"{tool}: the existing Debian binary is not executable."
    cmd = [
        ctl(), "exec", VM, "/usr/bin/env", f"PATH={GUEST_PATH}",
        spec.executable, *arguments(tool, value),
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
    except subprocess.TimeoutExpired:
        return f"{tool}: timed out after 120 seconds; no result verified."
    except OSError as exc:
        return f"{tool}: tool launch error ({type(exc).__name__})."
    out = (result.stdout + "\n" + result.stderr).strip()
    state = "completed" if result.returncode == 0 else "error"
    return (
        f"Debian OSINT tool: {tool}\nTarget: {value}\n"
        f"Exit status: {result.returncode}\nStatus: {state}\n\n"
        + (out[:12000] if out else "No tool output; not evidence of no matches.")
    )


async def search(tool: str, target: str) -> str:
    return await asyncio.to_thread(_execute, tool, target)
