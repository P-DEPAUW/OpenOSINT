"""Passive reverse-image search entrypoints.

No photo is uploaded, indexed or identified by OpenOSINT.  The analyst
chooses whether to submit a photo to an external visual search provider.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import quote, urlsplit

_PROVIDERS = (
    ("Google Lens", "https://lens.google.com/", "Upload the photo or paste its image URL."),
    ("TinEye", "https://tineye.com/", "Upload the photo or paste its image URL."),
    ("Yandex Images", "https://yandex.com/images/", "Upload the photo or use image search."),
)


def _is_image_file(path: Path) -> bool:
    """Check a small file header without optional dependencies or uploads."""
    with path.open("rb") as handle:
        header = handle.read(32)
    if header.startswith((b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"GIF87a", b"GIF89a", b"BM")):
        return True
    if header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return True
    if header.startswith((b"II*\x00", b"MM\x00*")):
        return True
    if len(header) >= 12 and header[4:8] == b"ftyp" and header[8:12] in (
        b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1", b"avif", b"avis"
    ):
        return True
    return False


def prepare_image_search(source: str | None = None) -> dict:
    """Validate an image file/HTTPS URL, and give safe, user-initiated search options.

    This function does not perform a reverse image search itself, open a browser,
    contact a provider or infer a person's identity or username.
    """
    source_type = "none"
    normalized = None
    if source is not None:
        if not source.strip():
            raise ValueError("The image source cannot be empty.")
        parsed = urlsplit(source)
        if parsed.scheme or parsed.netloc:
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError("Only public HTTPS image URLs without credentials are accepted.")
            source_type = "image_url"
            normalized = source
        else:
            path = Path(source).expanduser()
            if not path.is_file():
                raise ValueError("Image file not found or not a regular file.")
            if not _is_image_file(path):
                raise ValueError("Unsupported or invalid image file format.")
            source_type = "local_file"
            normalized = str(path.resolve())

    providers = [
        {"name": name, "url": url, "how": how}
        for name, url, how in _PROVIDERS
    ]
    if source_type == "image_url":
        # The public Yandex consumer URL has been checked, but the page itself
        # may ask for a human verification. No network call is made here.
        providers[2]["url"] = (
            "https://yandex.com/images/search?rpt=imageview&url=" + quote(normalized, safe="")
        )
    return {
        "status": "ready_for_manual_search",
        "source_type": source_type,
        "source": normalized,
        "uploaded": False,
        "search_performed": False,
        "matches": [],
        "providers": providers,
        "note": (
            "Open a provider and choose to submit the image yourself. "
            "Matching webpages may show public usernames, but a match does not "
            "verify the identity of the pictured person."
        ),
    }
