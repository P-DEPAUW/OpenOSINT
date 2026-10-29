"""Free, best-effort public search fallback for OpenOSINT footprints.

Uses DuckDuckGo's public HTML search, not a paid API. Search results are
unverified leads, never proof that two identities represent the same person.
"""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import parse_qs, urlparse

import requests

_SEARCH_URL = "https://html.duckduckgo.com/html/"
_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) "
    "AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36"
)


class _ResultParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.results: list[tuple[str, str]] = []
        self._inside = False
        self._title = ""
        self._href = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        if tag == "a" and "result__a" in (attr.get("class") or "").split():
            self._inside = True
            self._title = ""
            self._href = attr.get("href") or ""

    def handle_data(self, data: str) -> None:
        if self._inside:
            self._title += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._inside:
            self.results.append((self._title.strip(), self._href))
            self._inside = False


def _destination(href: str) -> str:
    """Unwrap DDG redirect links without visiting the result website."""
    if href.startswith("//"):
        href = "https:" + href
    parsed = urlparse(href)
    if parsed.hostname in {"duckduckgo.com", "www.duckduckgo.com"}:
        href = parse_qs(parsed.query).get("uddg", [""])[0]
        parsed = urlparse(href)
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        return ""
    if parsed.username or parsed.password:
        return ""
    return href


def search_free_footprint(target: str, queries: list[str], timeout_seconds: int) -> str:
    """Collect public search results, reporting blocks/errors explicitly."""
    lines = [
        f"[Footprint] {target} | free public search (DuckDuckGo)",
        "Search-engine results are leads, NOT confirmed identity matches.",
        "Queries are sent to DuckDuckGo from this computer.",
    ]
    seen_urls: set[str] = set()
    domains: set[str] = set()
    errors: list[str] = []
    all_tokens = [word.casefold() for word in target.split()]
    for number, query in enumerate(queries, start=1):
        lines.append(f"[+] Query {number}/{len(queries)}: {query}")
        try:
            response = requests.get(
                _SEARCH_URL,
                params={"q": query},
                headers={"User-Agent": _USER_AGENT},
                timeout=timeout_seconds,
            )
            response.raise_for_status()
            parser = _ResultParser()
            parser.feed(response.text)
            if not parser.results and ("anomaly" in response.text.lower() or "captcha" in response.text.lower()):
                raise RuntimeError("search engine requested human verification")
            added = 0
            for title, href in parser.results:
                url = _destination(href)
                if not url or url.rstrip("/") in seen_urls:
                    continue
                searchable = (title + " " + url).casefold()
                if all_tokens and not all(token in searchable for token in all_tokens):
                    continue
                seen_urls.add(url.rstrip("/"))
                host = urlparse(url).hostname or ""
                domains.add(host.removeprefix("www."))
                lines.append(f"    {len(seen_urls)}. {title}")
                lines.append(f"       URL: {url}")
                lines.append(f"[Footprint] URL: {url}")
                added += 1
                if added >= 10:
                    break
            if not added:
                lines.append("    (no matching indexed results; not proof of absence)")
        except (requests.RequestException, RuntimeError) as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
            lines.append(f"    (search unavailable: {type(exc).__name__})")
    if len(errors) == len(queries):
        return "Scan error: free public search unavailable. " + "; ".join(errors)
    if not seen_urls:
        return (
            "\n".join(lines)
            + "\nNo matching indexed pages found. This does not verify or disprove an identity."
        )
    lines.append(f"[Footprint] Matches: {len(seen_urls)} public search results (unverified)")
    for domain in sorted(domains):
        lines.append(f"[Footprint] Domain: {domain}")
    return "\n".join(lines)


def search_available_footprint(
    target: str, queries: list[str], timeout_seconds: int, serpapi_key: str = ""
) -> str:
    """Prefer existing SerpApi free quota, then best-effort public HTML search.

    Never spend paid SerpApi credits or expose the secret in output.
    """
    if serpapi_key:
        try:
            account = requests.get(
                "https://serpapi.com/account.json",
                params={"api_key": serpapi_key},
                timeout=timeout_seconds,
            )
            account.raise_for_status()
            status = account.json()
            remaining = int(status.get("total_searches_left") or 0)
            free_plan = float(status.get("plan_monthly_price") or 0) == 0
            if status.get("account_status") == "Active" and free_plan and remaining >= len(queries):
                result = _search_serpapi(target, queries, timeout_seconds, serpapi_key)
                if result is not None:
                    return result
        except (requests.RequestException, ValueError, TypeError):
            pass
    return search_free_footprint(target, queries, timeout_seconds)


def _search_serpapi(
    target: str, queries: list[str], timeout_seconds: int, api_key: str
) -> str | None:
    lines = [
        f"[Footprint] {target} | SerpApi Google Search (existing free plan)",
        "Search results are unverified leads; not proof of an identity match.",
        f"Free-plan search queries: {len(queries)}",
    ]
    seen: set[str] = set()
    domains: set[str] = set()
    tokens = [token.casefold() for token in target.split()]
    for number, query in enumerate(queries, start=1):
        try:
            response = requests.get(
                "https://serpapi.com/search.json",
                params={"engine": "google", "q": query, "api_key": api_key, "num": 10},
                timeout=timeout_seconds,
            )
            response.raise_for_status()
            payload = response.json()
            if "error" in payload:
                return None
            results = payload.get("organic_results", [])
        except (requests.RequestException, ValueError, TypeError):
            # No exceptions printed: requests can embed the API key in its URL.
            return None
        lines.append(f"[+] Query {number}/{len(queries)}: {query}")
        added = 0
        for hit in results:
            url = _destination(hit.get("link", ""))
            title = str(hit.get("title") or "")
            if not url or url.rstrip("/") in seen:
                continue
            if not all(token in (title + " " + url).casefold() for token in tokens):
                continue
            seen.add(url.rstrip("/"))
            domains.add((urlparse(url).hostname or "").removeprefix("www."))
            lines.extend((
                f"    {len(seen)}. {title}",
                f"       URL: {url}",
                f"[Footprint] URL: {url}",
            ))
            added += 1
        if not added:
            lines.append("    (no matching indexed results; not proof of absence)")
    if not seen:
        lines.append("No matching indexed pages found. This does not verify or disprove an identity.")
    else:
        lines.append(f"[Footprint] Matches: {len(seen)} public search results (unverified)")
        for domain in sorted(domains):
            lines.append(f"[Footprint] Domain: {domain}")
    return "\n".join(lines)
