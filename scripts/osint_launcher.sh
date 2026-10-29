#!/bin/sh
# Existing OSINT entry point: the Mac always works; Debian is an optional tool backend.
set -eu
bin="$HOME/Developer/OpenOSINT/.venv/bin/openosint"
if [ ! -x "$bin" ]; then
  echo "OpenOSINT on Mac is not available at its existing path." >&2
  exit 69
fi
# Only the tool invocation may start the existing Debian VM, when T9 is mounted.
export OPENOSINT_AUTOSTART_DEBIAN=1

case "${1:-}" in
  ai)
    shift
    # Preserve the pre-existing macOS Keychain integration for Shodan.
    if /usr/bin/security find-generic-password -s H0M3-OpenOSINT-Shodan -a "$USER" >/dev/null 2>&1; then
      shodan_secret=$(/usr/bin/security find-generic-password -s H0M3-OpenOSINT-Shodan -a "$USER" -w 2>/dev/null) || shodan_secret=
      if [ -n "$shodan_secret" ]; then
        export SHODAN_API_KEY="$shodan_secret"
      fi
      unset shodan_secret
    fi
    exec "$bin" --provider ollama --ollama-model qwen3.5:4b --ollama-host http://127.0.0.1:11434 --allow-active "$@"
    ;;
  debian)
    shift
    if ! /sbin/mount | /usr/bin/grep -q ' on /Volumes/T9 '; then
      echo "Debian unavailable: T9 is not mounted. The Mac OSINT menu remains available: osint" >&2
      exit 69
    fi
    if ! /usr/local/bin/prlctl status "Debian VM" 2>/dev/null | /usr/bin/grep -q 'exist running'; then
      /usr/local/bin/prlctl start "Debian VM" >&2 || exit $?
    fi
    exec /usr/local/bin/prlctl exec "Debian VM" /usr/local/bin/osint "$@"
    ;;
  *)
    # The keyless Mac tools menu never depends on Debian/T9.
    exec "$bin" "$@"
    ;;
esac
