#!/usr/bin/env python3
"""Reuse existing Parallels Debian OSINT binaries when T9 is mounted.

This is an opt-in PATH shim, not a VM install or new service. If the guest or
tool is missing, use an existing macOS binary when available.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

GUEST_TOOLS = {
    "sherlock": "/usr/bin/sherlock",
    "holehe": "/usr/local/bin/holehe",
    "sublist3r": "/usr/bin/sublist3r",
    "phoneinfoga": None,  # Current Debian guest has no phoneinfoga binary.
}
VM = "Debian VM"
BRIDGE_DIR = Path.home() / ".config/h0m3/osint-debian-bin"


def _native_path(tool: str) -> str | None:
    # Do not recursively resolve our own PATH shims.
    paths = [
        p for p in os.environ.get("PATH", "").split(os.pathsep)
        if p and Path(p).resolve() != BRIDGE_DIR.resolve()
    ]
    return shutil.which(tool, path=os.pathsep.join(paths))


def guest_available() -> bool:
    if not os.path.ismount("/Volumes/T9"):
        return False
    if not Path("/Volumes/T9/VMs/Debian").exists():
        return False
    ctl = shutil.which("prlctl") or "/usr/local/bin/prlctl"
    try:
        status = subprocess.run(
            [ctl, "status", VM], timeout=5, capture_output=True, text=True,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if status.returncode != 0:
        return False
    if "exist running" in status.stdout:
        return True
    if "exist stopped" not in status.stdout:
        return False
    # Start lazily only when the user actually invokes a Debian-backed tool.
    if os.environ.get("OPENOSINT_AUTOSTART_DEBIAN") != "1":
        return False
    try:
        started = subprocess.run(
            [ctl, "start", VM], timeout=65, capture_output=True, text=True,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return started.returncode == 0


def main() -> int:
    tool = Path(sys.argv[0]).name
    if tool not in GUEST_TOOLS:
        print("Unsupported OSINT binary.", file=sys.stderr)
        return 2
    guest_binary = GUEST_TOOLS[tool]
    if guest_binary and guest_available():
        ctl = shutil.which("prlctl") or "/usr/local/bin/prlctl"
        # No shell expansion: each value stays a distinct argument.
        os.execv(ctl, [ctl, "exec", VM, guest_binary, *sys.argv[1:]])
    native = _native_path(tool)
    if native:
        os.execv(native, [native, *sys.argv[1:]])
    print(
        f"{tool}: unavailable (Parallels Debian/T9 unavailable and no macOS binary).",
        file=sys.stderr,
    )
    return 69


if __name__ == "__main__":
    raise SystemExit(main())
