"""Known JA4 fingerprints, for the "looks like" line.

Every entry was measured with scraper-leak-check's own echo server on the
date noted (self-generated reference data; see tests/data/). Fingerprints
shift with client versions, so a miss only means "not one of the few we
know" — the raw lists are always shown for a real comparison, and the
public databases (ja4db.com) cover far more clients than this file.
"""
from __future__ import annotations

# ja4 -> (label, measured_with, date)
KNOWN: dict[str, tuple[str, str, str]] = {
    "t13i1515h2_8daaf6152771_2f874e5dbbd9": (
        "a Chromium browser (this build; SNI absent because the target was an IP)",
        "in-app Chromium, scraper-leak-check echo", "2026-11-08",
    ),
    "t13d3112h2_e8f1e7e78f70_8d633dac7124": (
        "curl 7.87.0 (OpenSSL build, Git for Windows)",
        "curl 7.87.0 via tls.browserleaks.com, byte-identical", "2026-11-08",
    ),
    "t13i3111h2_e8f1e7e78f70_8d633dac7124": (
        "curl 7.87.0 (OpenSSL build; SNI absent because the target was an IP)",
        "curl 7.87.0, scraper-leak-check echo", "2026-11-08",
    ),
    "t13i180900_85036bcba153_1f22a2ca17c4": (
        "Python 3.14 stdlib client (urllib, no ALPN, no SNI to an IP)",
        "python 3.14 urllib, scraper-leak-check echo", "2026-11-08",
    ),
}


def label_for(ja4: str) -> str | None:
    entry = KNOWN.get(ja4)
    return entry[0] if entry else None


def structural_hint(info: dict) -> str | None:
    """A cautious hint from the shape of the fingerprint alone."""
    tls = info.get("tls", info)
    version = tls.get("tls_version")
    alpn = tls.get("alpn") or []
    ciphers = tls.get("cipher_count", 0)
    extensions = tls.get("extension_count", 0)
    if version == "13" and "h2" in alpn and ciphers >= 15 and extensions >= 15:
        return "browser-shaped (TLS 1.3, h2 offered, many ciphers and extensions)"
    if version == "13" and not alpn:
        return "non-browser client (no ALPN: browsers always offer h2)"
    if ciphers <= 5:
        return "minimal client (few cipher suites)"
    return None
