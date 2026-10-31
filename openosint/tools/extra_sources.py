"""Optional OSINT sources: passive public archives, opt-in Lens and host check.

No file is uploaded and no paid request is made without a configured API key.
All lookups are bounded, return explicit errors and preserve the original tools.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

import requests

_DOMAIN = re.compile(r"(?=.{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\Z", re.I)
_MAX_BYTES = 3_000_000


def _domain(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("A domain name is required.")
    name = value.strip().lower().rstrip(".")
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid domain name.") from exc
    if not _DOMAIN.fullmatch(name) or name.endswith((".local", ".internal", ".localhost")):
        raise ValueError("Provide a public domain such as example.com (not a URL or IP).")
    return name


def _image_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError("Lens requires a public HTTPS image URL without credentials.")
    host = parsed.hostname
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        _domain(host)
    else:
        if not addr.is_global:
            raise ValueError("Local/private image URLs are forbidden.")
    if len(value) > 2048 or not parsed.path:
        raise ValueError("Provide an HTTPS URL pointing to a public image.")
    return value


def _json_get(url: str, *, params: dict, timeout_seconds: int, headers: dict | None = None):
    """Bound response bytes and time; omit potentially secret request URLs in errors."""
    try:
        with requests.get(url, params=params, headers=headers or {}, timeout=(5, min(max(timeout_seconds, 5), 30)), stream=True) as response:
            if response.status_code != 200:
                return None, f"Provider HTTP {response.status_code}; availability/quotas may vary."
            chunks = []
            size = 0
            for chunk in response.iter_content(64 * 1024):
                size += len(chunk)
                if size > _MAX_BYTES:
                    return None, "Provider response too large; no data imported."
                chunks.append(chunk)
            try:
                return json.loads(b"".join(chunks)), None
            except (ValueError, UnicodeError):
                return None, "Provider did not return valid JSON."
    except requests.RequestException as exc:
        return None, f"Provider request failed ({type(exc).__name__}); no results verified."


def _certificates_sync(domain: str, timeout_seconds: int = 20) -> str:
    name = _domain(domain)
    # SSLMate documents anonymous personal/evaluation access, but quota varies.
    data, err = _json_get("https://api.certspotter.com/v1/issuances", params={"domain": name, "include_subdomains": "true", "expand": "dns_names"}, timeout_seconds=timeout_seconds)
    source = "SSLMate Cert Spotter (unexpired certificates)"
    if err:
        # crt.sh can be slow/unavailable; a fallback, never the single failure point.
        data, fallback_error = _json_get("https://crt.sh/", params={"q": "%." + name, "output": "json"}, timeout_seconds=min(timeout_seconds, 9))
        if fallback_error:
            return f"Certificate Transparency for {name}: Cert Spotter {err}; crt.sh {fallback_error}"
        source = "crt.sh certificate transparency (historical index)"
    if not isinstance(data, list):
        return f"Certificate Transparency for {name}: unexpected provider response."
    hostnames = []
    for row in data:
        if not isinstance(row, dict):
            continue
        hostnames.extend(row.get("dns_names", []) if isinstance(row.get("dns_names", []), list) else [])
        hostnames.extend(str(row.get("name_value", "")).splitlines())
    hosts = sorted({host.lower().removeprefix("*.") for entry in hostnames if isinstance(entry, str) for host in [entry.strip()] if host.lower().removeprefix("*.") == name or host.lower().removeprefix("*.").endswith("." + name)})
    return json.dumps({"source": source, "domain": name, "host_count_in_response": len(hosts), "hosts": hosts[:100], "truncated": len(hosts) > 100, "note": "Certificate issuances are leads, not proof of currently active services; the sources have different date coverage."}, ensure_ascii=False)

async def run_certificates_osint(domain: str, timeout_seconds: int = 20) -> str:
    return await asyncio.to_thread(_certificates_sync, domain, timeout_seconds)


def _archive_sync(domain: str, timeout_seconds: int = 20) -> str:
    name = _domain(domain)
    # CDX supports historical enumeration, but is frequently slow or rate-limited.
    data, err = _json_get("https://web.archive.org/cdx/search/cdx", params={"url": name, "matchType": "domain", "output": "json", "filter": "statuscode:200", "collapse": "urlkey", "limit": 25}, timeout_seconds=min(timeout_seconds, 6))
    captures = []
    if not err and isinstance(data, list) and data and isinstance(data[0], list):
        headers = data[0]
        for row in data[1:26]:
            if not isinstance(row, list) or len(row) != len(headers):
                continue
            item = dict(zip(headers, row))
            original = item.get("original", "")
            host = urlsplit(original).hostname
            if host and (host == name or host.endswith("." + name)):
                captures.append({"url": original, "timestamp": item.get("timestamp", "")})
        return json.dumps({"source": "Internet Archive Wayback CDX", "domain": name, "captures": captures, "limit": 25, "note": "Historical index only; not current website content."}, ensure_ascii=False)
    # Official nearest-snapshot availability endpoint is a graceful fallback.
    available, fallback_error = _json_get("https://archive.org/wayback/available", params={"url": name}, timeout_seconds=timeout_seconds)
    if fallback_error:
        return f"Wayback archive for {name}: CDX {err or 'no records'}; availability {fallback_error}"
    closest = (available or {}).get("archived_snapshots", {}).get("closest", {}) if isinstance(available, dict) else {}
    if isinstance(closest, dict) and closest.get("available"):
        archive_url = closest.get("url", "")
        if archive_url.startswith("http://web.archive.org/"):
            archive_url = "https://" + archive_url[len("http://"):]
        captures = [{"url": name, "timestamp": closest.get("timestamp", ""), "archive_url": archive_url}]
    return json.dumps({"source": "Internet Archive Wayback availability (nearest snapshot only)", "domain": name, "captures": captures, "limit": 1, "warning": "Full CDX historical index unavailable; this is only the closest snapshot.", "note": "Historical snapshot only; not current website content."}, ensure_ascii=False)

async def run_archive_osint(domain: str, timeout_seconds: int = 20) -> str:
    return await asyncio.to_thread(_archive_sync, domain, timeout_seconds)


def _lens_sync(image_url: str, timeout_seconds: int = 20) -> str:
    """Real Lens lookup: a public HTTPS URL OR a local JPEG/PNG/WebP upload.

    Local files are shared only with SerpApi; never hosted by this program.
    """
    if not isinstance(image_url, str) or not image_url.strip():
        raise ValueError("Lens needs a public HTTPS image URL or a local photo.")
    key = os.environ.get("SERPAPI_API_KEY", "").strip()
    if not key:
        return "Google Lens API not run: SERPAPI_API_KEY is missing. Nothing was uploaded."
    search = {"engine": "google_lens", "type": "all", "api_key": key}
    public_url = image_url.startswith("https://")
    if public_url:
        search["url"] = _image_url(image_url)
    else:
        source = Path(image_url).expanduser()
        if not source.is_file() or source.suffix.lower() not in {".jpg", ".jpeg", ".png", ".webp"}:
            raise ValueError("For uploads supply an existing local JPG, PNG or WebP photo.")
        if source.stat().st_size > 500_000:
            raise ValueError("SerpApi accepts up to 500 KB. Resize the local photo first.")
        mime = "image/png" if source.suffix.lower() == ".png" else (
            "image/webp" if source.suffix.lower() == ".webp" else "image/jpeg"
        )
        try:
            with source.open("rb") as photo:
                response = requests.post(
                    "https://serpapi.com/image",
                    files={"image": (source.name, photo, mime)},
                    data={"api_key": key},
                    timeout=(5, min(max(timeout_seconds, 6), 30)),
                )
            if response.status_code != 200 or len(response.content) > _MAX_BYTES:
                return f"Lens upload failed (HTTP {response.status_code}); no search ran."
            payload = response.json()
        except (requests.RequestException, ValueError) as exc:
            return f"Lens upload failed ({type(exc).__name__}); no search ran."
        image_id = payload.get("image_id") if isinstance(payload, dict) else None
        if not image_id:
            return "Lens upload rejected; check SerpApi quota or image format."
        search["image_id"] = image_id
    data, err = _json_get("https://serpapi.com/search.json", params=search, timeout_seconds=timeout_seconds)
    if err:
        return f"Google Lens API: {err}"
    if not isinstance(data, dict):
        return "Google Lens API returned unexpected data."
    if data.get("error"):
        return "Google Lens API rejected request (check SerpApi account/quota)."
    matches = []
    for match in data.get("visual_matches", [])[:20]:
        if isinstance(match, dict):
            matches.append({k: match.get(k) for k in ("title", "link", "source", "image", "exact_matches") if match.get(k) is not None})
    return json.dumps({
        "source": "SerpApi Google Lens", "input_type": "public_url" if public_url else "local_upload",
        "uploaded_to_serpapi": not public_url, "matches": matches, "count": len(matches),
        "note": "Visual similarity is not identity. Local uploads are shared with SerpApi, not publicly hosted.",
    }, ensure_ascii=False)


async def run_lens_osint(image_url: str, timeout_seconds: int = 20) -> str:
    return await asyncio.to_thread(_lens_sync, image_url, timeout_seconds)


def _nmap_sync(target: str, timeout_seconds: int = 25) -> str:
    """Bounded active host service check, only when explicitly enabled in the caller policy."""
    if not isinstance(target, str) or not target.strip() or len(target) > 253:
        raise ValueError("A single authorized hostname or IP is required.")
    host = target.strip()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        host = _domain(host)
    nmap = shutil.which("nmap")
    if not nmap:
        return "Nmap not installed on this Mac. No scan performed."
    args = [nmap, "-sT", "-Pn", "--open", "-T2", "--max-retries", "1", "-p", "22,80,443,445,8080", "--", host]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=min(max(timeout_seconds, 5), 30), check=False)
    except subprocess.TimeoutExpired:
        return f"Nmap for {host}: timed out; no complete result."
    output = result.stdout[-5000:]
    if result.returncode != 0:
        return f"Nmap for {host}: exit {result.returncode}. {result.stderr[:300]}"
    return f"Nmap limited TCP connectivity test (5 ports) for {host}:\n{output}\nActive scan: target network received probes."


async def run_nmap_osint(target: str, timeout_seconds: int = 25) -> str:
    # Guard within the callable as well, so direct Python use respects passive mode.
    from openosint.tool_policy import is_tool_enabled
    if not is_tool_enabled("scan_host_ports"):
        return "Nmap is disabled in passive mode. Use --allow-active on authorized targets only."
    return await asyncio.to_thread(_nmap_sync, target, timeout_seconds)


def _greynoise_sync(ip: str, timeout_seconds: int = 15) -> str:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError("GreyNoise expects a public IP address, not a hostname.") from exc
    if not address.is_global:
        raise ValueError("GreyNoise only accepts global public IP addresses.")
    token = os.environ.get("GREYNOISE_API_KEY", "").strip()
    headers = {"key": token} if token else {}
    data, err = _json_get(f"https://api.greynoise.io/v3/community/{address}", params={}, headers=headers, timeout_seconds=timeout_seconds)
    if err:
        return f"GreyNoise for {address}: {err} Free API rate limits or permission may apply."
    if not isinstance(data, dict):
        return f"GreyNoise for {address}: unexpected response."
    return json.dumps({"source": "GreyNoise Community API", "ip": str(address),
                       "noise": data.get("noise"), "riot": data.get("riot"),
                       "classification": data.get("classification"), "name": data.get("name"),
                       "link": data.get("link"),
                       "note": "Community observations, not an exhaustive security verdict."}, ensure_ascii=False)


async def run_greynoise_osint(ip: str, timeout_seconds: int = 15) -> str:
    return await asyncio.to_thread(_greynoise_sync, ip, timeout_seconds)


def _metadata_sync(path: str, timeout_seconds: int = 12) -> str:
    """Only inspect a local media file; never upload or change it."""
    from pathlib import Path
    if not isinstance(path, str) or not path.strip():
        raise ValueError("A local image or media path is required.")
    item = Path(path).expanduser()
    allowed = {".jpg", ".jpeg", ".png", ".webp", ".heic", ".heif", ".tiff", ".gif", ".avif", ".mp4", ".mov", ".pdf"}
    if item.suffix.lower() not in allowed or not item.is_file():
        raise ValueError("Provide an existing local image, video or PDF file.")
    if item.stat().st_size > 100 * 1024 * 1024:
        raise ValueError("Metadata file must be at most 100 MB.")
    binary = shutil.which("exiftool")
    if not binary:
        return "ExifTool not installed. No file read."
    tags = ["-FileType", "-ImageWidth", "-ImageHeight", "-Make", "-Model", "-DateTimeOriginal", "-CreateDate", "-GPSLatitude", "-GPSLongitude", "-Artist", "-Copyright", "-Software"]
    try:
        output = subprocess.run([binary, "-j", "-n", *tags, "--", str(item)], text=True, capture_output=True, timeout=min(max(timeout_seconds, 2), 20), check=False)
    except subprocess.TimeoutExpired:
        return "ExifTool timed out; no metadata output."
    if output.returncode:
        return f"ExifTool returned exit code {output.returncode}; no metadata verified."
    try:
        rows = json.loads(output.stdout)
    except ValueError:
        return "ExifTool response was not valid JSON."
    metadata = rows[0] if isinstance(rows, list) and rows and isinstance(rows[0], dict) else {}
    metadata.pop("SourceFile", None)
    return json.dumps({"source": "local ExifTool read-only", "tags": metadata,
                       "note": "GPS metadata, if present, is sensitive. No image uploaded."}, ensure_ascii=False)


async def run_metadata_osint(path: str, timeout_seconds: int = 12) -> str:
    return await asyncio.to_thread(_metadata_sync, path, timeout_seconds)
