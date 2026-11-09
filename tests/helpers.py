"""Synthetic ClientHello builders and spec-derived JA4 expectations.

The expected JA4 strings in test_fingerprints.py are computed HERE, from
raw cipher/extension lists, straight from the public JA4 specification —
deliberately NOT via scraper_leak_check.fingerprints, so a bug in the
production code cannot hide behind itself.
"""
from __future__ import annotations

import hashlib


def spec_ja4(ciphers: list[int], extensions: list[int], sigalgs: list[int], *,
             version: int = 0x0304, sni: bool = True, alpn: str | None = "h2",
             protocol_version: int = 0x0303) -> str:
    """Compute JA4 exactly as the FoxIO spec describes, from plain lists."""
    grease = {0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
              0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA}
    version_codes = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10"}
    alnum = set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

    ciphers_ng = [c for c in ciphers if c not in grease]
    exts_ng = [e for e in extensions if e not in grease]

    if alpn is None:
        hint = "00"
    else:
        head, tail = alpn[0], alpn[-1]
        if head in alnum and tail in alnum:
            hint = head + tail
        else:
            hx = alpn.encode("latin-1").hex()
            hint = hx[0] + hx[-1]

    part_a = (
        "t" + version_codes[version] + ("d" if sni else "i")
        + str(min(len(ciphers_ng), 99)).zfill(2)
        + str(min(len(exts_ng), 99)).zfill(2)
        + hint
    )
    sha = lambda s: hashlib.sha256(s.encode("ascii")).hexdigest()[:12]
    part_b = sha(",".join(f"{c:04x}" for c in sorted(ciphers_ng))) if ciphers_ng else "000000000000"
    ext_for_c = sorted(e for e in exts_ng if e not in (0x0000, 0x0010))
    joined = [",".join(f"{e:04x}" for e in ext_for_c), ",".join(f"{s:04x}" for s in sigalgs)]
    part_c_input = "_".join(p for p in joined if p)
    part_c = sha(part_c_input) if part_c_input else "000000000000"
    return f"{part_a}_{part_b}_{part_c}"


def build_client_hello(ciphers: list[int], extensions: list[tuple[int, bytes]], *,
                       legacy_version: int = 0x0303, supported_versions: list[int] | None = None,
                       sigalgs: list[int] | None = None, groups: list[int] | None = None,
                       point_formats: list[int] | None = None, sni: bytes = b"example.com",
                       alpn: list[bytes] | None = None) -> bytes:
    """Build a byte-exact TLS ClientHello inside one record + handshake."""
    def ext(code: int, value: bytes) -> bytes:
        return code.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value

    exts: list[tuple[int, bytes]] = []
    if sni is not None:
        name_entry = b"\x00" + len(sni).to_bytes(2, "big") + sni  # type + length + host
        exts.append((0x0000, len(name_entry).to_bytes(2, "big") + name_entry))
    if groups is not None:
        body = b"".join(g.to_bytes(2, "big") for g in groups)
        exts.append((0x000A, len(body).to_bytes(2, "big") + body))
    if point_formats is not None:
        body = bytes(point_formats)
        exts.append((0x000B, len(body).to_bytes(1, "big") + body))
    if sigalgs is not None:
        body = b"".join(s.to_bytes(2, "big") for s in sigalgs)
        exts.append((0x000D, len(body).to_bytes(2, "big") + body))
    if alpn is not None:
        protos = b"".join(len(p).to_bytes(1, "big") + p for p in alpn)
        exts.append((0x0010, len(protos).to_bytes(2, "big") + protos))
    if supported_versions is not None:
        body = b"".join(v.to_bytes(2, "big") for v in supported_versions)
        exts.append((0x002B, len(body).to_bytes(1, "big") + body))
    for code, value in extensions:  # caller's extras, in order
        exts.append((code, value))

    cipher_bytes = b"".join(c.to_bytes(2, "big") for c in ciphers)
    ext_bytes = b"".join(ext(c, v) for c, v in exts)
    body = (
        legacy_version.to_bytes(2, "big")
        + b"\x00" * 32  # random
        + b"\x00"  # empty session id
        + len(cipher_bytes).to_bytes(2, "big") + cipher_bytes
        + b"\x01\x00"  # one compression method: null
        + len(ext_bytes).to_bytes(2, "big") + ext_bytes
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
