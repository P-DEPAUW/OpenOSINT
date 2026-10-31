"""Offline tests: image-search helper must never upload or identify photos."""

from __future__ import annotations

import pytest

from openosint.image_search import prepare_image_search


def test_manual_providers_without_photo():
    result = prepare_image_search()
    assert result["search_performed"] is False
    assert result["uploaded"] is False
    assert len(result["providers"]) == 3
    assert result["matches"] == []


def test_local_png_recognized_without_upload(tmp_path):
    image = tmp_path / "safe image.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 20)
    result = prepare_image_search(str(image))
    assert result["source_type"] == "local_file"
    assert result["source"] == str(image)
    assert not result["uploaded"]


def test_public_https_url_creates_encoded_yandex_lookup():
    result = prepare_image_search("https://example.org/my photo.png?x=1&y=2")
    assert result["source_type"] == "image_url"
    assert "my%20photo.png%3Fx%3D1%26y%3D2" in result["providers"][2]["url"]
    assert result["search_performed"] is False


@pytest.mark.parametrize("source", ["", "ftp://example.org/test.jpg", "file:///etc/passwd", "https://a:b@example.com/a.jpg", "http://example.com/a.png", "https://"])
def test_reject_invalid_or_unsafe_urls(source):
    with pytest.raises(ValueError):
        prepare_image_search(source)


def test_reject_non_image_file(tmp_path):
    path = tmp_path / "secret.txt"
    path.write_text("not a picture")
    with pytest.raises(ValueError):
        prepare_image_search(str(path))


def test_reject_missing_local_file(tmp_path):
    with pytest.raises(ValueError):
        prepare_image_search(str(tmp_path / "missing.jpg"))


def test_cli_parser_keeps_existing_subcommands():
    from openosint.cli import _build_parser

    parser = _build_parser()
    assert parser.parse_args(["username", "johndoe"]).command == "username"
    assert parser.parse_args(["email", "someone@example.org"]).command == "email"
    assert parser.parse_args(["image"]).source is None
    assert parser.parse_args(["image", "https://example.org/photo.jpg"]).command == "image"
