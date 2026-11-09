"""JA4 and JA3 fingerprints of a parsed ClientHello.

JA4 follows the public specification by FoxIO (BSD 3-Clause):
https://github.com/FoxIO-LLC/ja4 — implemented here from the spec text,
not copied from any implementation. Format: `a_b_c`, where

  a = protocol(t) + version(2) + SNI(d/i) + cipher count(2) + extension
      count(2) + ALPN hint(2)          e.g.  t13d1516h2
  b = sha256(sorted non-GREASE cipher hexes)[:12]
  c = sha256(sorted extensions minus SNI/ALPN + '_' + signature algorithms
      in original order)[:12]

JA3 is the classic Salesforce format: md5 of
"version,ciphers,extensions,curves,point_formats" with '-' inside lists,
original order, GREASE removed.
"""
from __future__ import annotations

import hashlib

from .clienthello import (
    ClientHello,
    EXT_ALPN,
    EXT_SNI,
)

# RFC 8701 GREASE values, spelled out so the set is obvious.
GREASE = frozenset({
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
})

VERSION_CODES = {
    0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3",
    0x0002: "s2", 0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3",
}
SCSV = frozenset({0x00FF, 0x5600})
ALNUM = set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


def _sha12(text: str) -> str:
    return hashlib.sha256(text.encode("ascii")).hexdigest()[:12]


def _alpn_hint(alpn: list[str]) -> str:
    """First and last ASCII-alphanumeric chars of the first ALPN value."""
    if not alpn:
        return "00"
    first = alpn[0]
    if not first:
        return "00"
    head, tail = first[0], first[-1]
    if head in ALNUM and tail in ALNUM:
        return f"{head}{tail}"
    # Non-alphanumeric bytes: first and last characters of the hex form.
    raw = first.encode("latin-1")
    hx = raw.hex()
    return f"{hx[0]}{hx[-1]}"


def _ja4_version(hello: ClientHello) -> str:
    versions = [v for v in hello.supported_versions if v not in GREASE]
    chosen = max(versions) if versions else hello.legacy_version
    return VERSION_CODES.get(chosen, "00")


def ja4(hello: ClientHello) -> str:
    """The JA4 fingerprint, e.g. `t13d1516h2_8daaf6152771_e5627efa2ab1`."""
    protocol = "t"  # TLS over TCP; QUIC ('q') and DTLS ('d') start elsewhere

    sni_flag = "d" if hello.sni else "i"

    ciphers = [c for c in hello.cipher_suites if c not in GREASE]
    cipher_count = min(len(ciphers), 99)

    extensions = [code for code, _ in hello.extensions if code not in GREASE]
    extension_count = min(len(extensions), 99)

    part_a = (
        f"{protocol}{_ja4_version(hello)}{sni_flag}"
        f"{cipher_count:02d}{extension_count:02d}{_alpn_hint(hello.alpn)}"
    )

    ciphers_sorted = sorted(ciphers)
    part_b = _sha12(",".join(f"{c:04x}" for c in ciphers_sorted)) if ciphers_sorted else "000000000000"

    ext_sorted = sorted(code for code in extensions if code not in (EXT_SNI, EXT_ALPN))
    ext_hexes = [f"{code:04x}" for code in ext_sorted]
    sig_hexes = [f"{s:04x}" for s in hello.signature_algorithms]
    part_c_input = "_".join(filter(None, [",".join(ext_hexes), ",".join(sig_hexes)]))
    part_c = _sha12(part_c_input) if part_c_input else "000000000000"

    return f"{part_a}_{part_b}_{part_c}"


def ja4_raw(hello: ClientHello) -> str:
    """`JA4_ro`: the raw lists in original order, GREASE removed, SNI/ALPN kept."""
    ciphers = ",".join(f"{c:04x}" for c in hello.cipher_suites if c not in GREASE)
    extensions = ",".join(
        f"{code:04x}" for code, _ in hello.extensions if code not in GREASE
    )
    sigs = ",".join(f"{s:04x}" for s in hello.signature_algorithms)
    protocol = "t"
    sni_flag = "d" if hello.sni else "i"
    head = (
        f"{protocol}{_ja4_version(hello)}{sni_flag}"
        f"{min(len([c for c in hello.cipher_suites if c not in GREASE]), 99):02d}"
        f"{min(len([code for code, _ in hello.extensions if code not in GREASE]), 99):02d}"
        f"{_alpn_hint(hello.alpn)}"
    )
    return "_".join([head, ciphers, "_".join(filter(None, [extensions, sigs]))])


def ja3(hello: ClientHello) -> str:
    """The classic JA3 digest (Salesforce format, original order, no GREASE)."""
    version = hello.legacy_version
    ciphers = [c for c in hello.cipher_suites if c not in GREASE]
    extensions = [code for code, _ in hello.extensions if code not in GREASE]
    fields = [
        str(version),
        "-".join(f"{c:04x}" for c in ciphers),
        "-".join(f"{code:04x}" for code in extensions),
        "-".join(f"{g:04x}" for g in hello.supported_groups),
        "-".join(f"{p:02x}" for p in hello.ec_point_formats),
    ]
    return hashlib.md5(",".join(fields).encode("ascii")).hexdigest()


def summary(hello: ClientHello) -> dict:
    """Everything the echo server reports about the TLS layer."""
    return {
        "ja4": ja4(hello),
        "ja4_raw": ja4_raw(hello),
        "ja3": ja3(hello),
        "tls_version": _ja4_version(hello),
        "sni": hello.sni,
        "alpn": hello.alpn,
        "cipher_count": len([c for c in hello.cipher_suites if c not in GREASE]),
        "extension_count": len([c for c, _ in hello.extensions if c not in GREASE]),
        "ciphers": [f"{c:04x}" for c in hello.cipher_suites if c not in GREASE],
        "extensions": [f"{code:04x}" for code, _ in hello.extensions if code not in GREASE],
        "signature_algorithms": [f"{s:04x}" for s in hello.signature_algorithms],
        "supported_groups": [f"{g:04x}" for g in hello.supported_groups],
    }
