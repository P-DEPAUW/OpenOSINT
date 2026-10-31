"""Regression tests for OpenOSINT tool repairs: no network calls or real scans."""
from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest

from openosint import mcp_server
from openosint.tools import debian_collection as debian
from openosint.tools import extra_sources as lens


def test_lens_upload_local_png(monkeypatch, tmp_path):
    f = tmp_path / "my-picture.png"
    f.write_bytes(b"\x89PNG\r\n\x1a\n")
    monkeypatch.setenv("SERPAPI_API_KEY", "unit-test-not-real")
    seen = {}

    def fake_post(url, *, files, data, timeout):
        assert url == "https://serpapi.com/image"
        assert files["image"][0] == "my-picture.png"
        assert data["api_key"] == "unit-test-not-real"
        return SimpleNamespace(status_code=200, content=b'{"image_id":"private-id"}',
                               json=lambda: {"image_id": "private-id"})

    def fake_get(url, *, params, timeout_seconds):
        seen.update(params)
        return {"visual_matches": [{"title": "known match", "link": "https://example.com/photo"}]}, None

    monkeypatch.setattr(lens.requests, "post", fake_post)
    monkeypatch.setattr(lens, "_json_get", fake_get)
    result = json.loads(lens._lens_sync(str(f)))
    assert seen["image_id"] == "private-id"
    assert "url" not in seen
    assert result["input_type"] == "local_upload"
    assert result["count"] == 1
    assert "private-id" not in json.dumps(result)


def test_lens_refuses_oversize_and_unsupported(monkeypatch, tmp_path):
    monkeypatch.setenv("SERPAPI_API_KEY", "unit-test-not-real")
    large = tmp_path / "large.png"
    large.write_bytes(b"x" * 500001)
    with pytest.raises(ValueError, match="500 KB"):
        lens._lens_sync(str(large))
    bad = tmp_path / "document.txt"
    bad.write_text("not an image")
    with pytest.raises(ValueError, match="JPG"):
        lens._lens_sync(str(bad))


@pytest.mark.asyncio
async def test_mcp_paste_failure_is_not_success(monkeypatch):
    async def broken(_query, timeout_seconds):
        return "Scan error: upstream unavailable"
    monkeypatch.setattr(mcp_server, "_HANDLERS", {
        **mcp_server._HANDLERS,
        "search_paste": (lambda a: broken(a["query"], 15), lambda a: a["query"])
    })
    result = await mcp_server.call_tool("search_paste", {"query": "example.com"})
    assert result.isError is True


def test_spiderfoot_runs_python_directly(monkeypatch):
    commands = []
    monkeypatch.setattr(debian, "vm_status", lambda: "running")
    monkeypatch.setattr(debian, "ctl", lambda: "/usr/local/bin/prlctl")

    def fake_run(args, **kwargs):
        commands.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="scan complete", stderr="")

    monkeypatch.setattr(debian.subprocess, "run", fake_run)
    output = debian._execute("spiderfoot", "example.com")
    assert "Status: completed" in output
    launch = commands[-1]
    assert "/opt/owen/tools/OSINT/spiderfoot/.venv-linux/bin/python" in launch
    assert "/opt/owen/tools/OSINT/spiderfoot/sf.py" in launch
    assert "-u" in launch and "passive" in launch
