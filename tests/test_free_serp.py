"""Free public-search parser tests; no external requests."""

from unittest.mock import MagicMock, patch

import requests

from openosint.free_serp import _destination, search_free_footprint


def test_redirect_unwrap():
    url = "//duckduckgo.com/l/?uddg=https%3A%2F%2Ffacebook.com%2Fuser"
    assert _destination(url) == "https://facebook.com/user"
    assert _destination("javascript:alert(1)") == ""
    assert _destination("https://user:pass@host.com/") == ""


def test_filters_unrelated_identity_and_deduplicates():
    response = MagicMock(status_code=200)
    response.text = (
        '<a class="result__a" href="https://facebook.com/janeexample">Jane Example</a>'
        '<a class="result__a" href="https://facebook.com/janeexample">Jane Example</a>'
        '<a class="result__a" href="https://facebook.com/kimother">Unrelated Result</a>'
    )
    with patch("openosint.free_serp.requests.get", return_value=response):
        result = search_free_footprint("Jane Example", ['"Jane Example"'], 5)
    assert result.count("[Footprint] URL:") == 1
    assert "Unrelated Result" not in result
    assert "Matches: 1" in result


def test_reports_block_as_error_not_empty_success():
    with patch(
        "openosint.free_serp.requests.get",
        side_effect=requests.exceptions.Timeout("timeout"),
    ):
        result = search_free_footprint("Jane Example", ['"Jane Example"'], 5)
    assert result.startswith("Scan error:")
    assert "Timeout" in result


def test_reports_no_matches_as_uncertainty():
    response = MagicMock(status_code=200)
    response.text = '<a class="result__a" href="https://example.com/other">Else Else</a>'
    with patch("openosint.free_serp.requests.get", return_value=response):
        result = search_free_footprint("Jane Example", ['"Jane Example"'], 5)
    assert "No matching indexed pages" in result
    assert "[Footprint] URL:" not in result


def test_existing_free_serpapi_plan_returns_real_structured_results():
    from openosint.free_serp import search_available_footprint

    account = MagicMock(status_code=200)
    account.json.return_value = {
        "account_status": "Active",
        "plan_monthly_price": 0.0,
        "total_searches_left": 20,
    }
    search = MagicMock(status_code=200)
    search.json.return_value = {
        "organic_results": [
            {"title": "Jane Example - Public Profile", "link": "https://example.org/jane-example"},
            {"title": "Unrelated Person", "link": "https://example.org/unrelated"},
        ]
    }
    with patch("openosint.free_serp.requests.get", side_effect=[account, search]) as get:
        result = search_available_footprint("Jane Example", ['"Jane Example"'], 5, "secret-test-key")
    assert "existing free plan" in result
    assert "https://example.org/jane-example" in result
    assert "Unrelated Person" not in result
    assert "secret-test-key" not in result
    assert get.call_count == 2


def test_paid_serpapi_plan_uses_free_public_fallback():
    from openosint.free_serp import search_available_footprint

    account = MagicMock(status_code=200)
    account.json.return_value = {
        "account_status": "Active",
        "plan_monthly_price": 50,
        "total_searches_left": 20,
    }
    html = MagicMock(status_code=200)
    html.text = '<a class="result__a" href="https://example.org/jane-example">Jane Example</a>'
    with patch("openosint.free_serp.requests.get", side_effect=[account, html]) as get:
        result = search_available_footprint("Jane Example", ['"Jane Example"'], 5, "secret-test-key")
    assert "DuckDuckGo" in result
    assert "https://example.org/jane-example" in result
    assert get.call_count == 2
