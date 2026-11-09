"""Parse a TLS ClientHello from raw bytes.

Pure stdlib, no dependencies. Reads only the pieces JA3/JA4 need:
the legacy version field, cipher suites, extensions (order preserved) and,
inside them, SNI, ALPN, supported groups, EC point formats, signature
algorithms and supported_versions. Fragmented handshakes (a ClientHello
split across several TLS records or TCP segments) are reassembled by
`read_client_hello` from the socket.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass, field

HANDSHAKE_TYPE = 0x16
CLIENT_HELLO = 0x01
EXT_SNI = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIG_ALGS = 0x000D
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B


class ClientHelloError(ValueError):
    """The bytes are not a complete, well-formed ClientHello."""


@dataclass
class ClientHello:
    record_version: int  # the TLS record's version field (e.g. 0x0303)
    legacy_version: int  # the ClientHello body's version field
    cipher_suites: list[int] = field(default_factory=list)  # original order
    extensions: list[tuple[int, bytes]] = field(default_factory=list)  # original order
    compression: list[int] = field(default_factory=list)

    # -- extension views (filled by parse) ------------------------------------
    sni: str | None = None
    alpn: list[str] = field(default_factory=list)
    supported_groups: list[int] = field(default_factory=list)
    ec_point_formats: list[int] = field(default_factory=list)
    signature_algorithms: list[int] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)

    def ext_codes(self) -> list[int]:
        return [code for code, _ in self.extensions]


class _Reader:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ClientHelloError("truncated ClientHello")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def uint(self, n: int) -> int:
        return int.from_bytes(self.take(n), "big")

    def vector(self, len_bytes: int) -> "_Reader":
        return _Reader(self.take(self.uint(len_bytes)))


def _parse_sni(value: bytes) -> str | None:
    try:
        names = _Reader(value).vector(2)  # server_name_list
        while names.pos < len(names.data):
            names.uint(1)  # name_type (host_name = 0)
            name = names.vector(2).data
            if name:
                try:
                    return name.decode("idna")
                except ValueError:
                    return name.decode("latin-1", "replace")
    except ClientHelloError:
        pass
    return None


def _parse_alpn(value: bytes) -> list[str]:
    out: list[str] = []
    try:
        r = _Reader(value)
        proto = r.vector(2)
        while proto.pos < len(proto.data):
            out.append(proto.vector(1).data.decode("latin-1"))
    except ClientHelloError:
        pass
    return out


def _parse_uint16_list(value: bytes) -> list[int]:
    if len(value) < 2:
        return []
    body = value[2:]  # the list carries its own 2-byte length
    return [int.from_bytes(body[i : i + 2], "big") for i in range(0, len(body) - 1, 2)]


def parse_client_hello(data: bytes) -> ClientHello:
    """Parse one ClientHello from the start of `data` (records reassembled)."""
    r = _Reader(data)
    if r.uint(1) != HANDSHAKE_TYPE:
        raise ClientHelloError("not a TLS handshake record")
    record_version = r.uint(2)
    body = r.vector(2)  # the record body, length-prefixed
    if body.uint(1) != CLIENT_HELLO:
        raise ClientHelloError("not a ClientHello")
    hello = body.vector(3)  # the handshake message, length-prefixed

    hello = _Reader(hello.data)  # type-safe shadow: the message body from here
    ch = ClientHello(record_version=record_version, legacy_version=hello.uint(2))
    hello.take(32)  # random
    hello.vector(1)  # session id
    ciphers = hello.vector(2).data
    ch.cipher_suites = [int.from_bytes(ciphers[i : i + 2], "big")
                        for i in range(0, len(ciphers), 2)]
    ch.compression = list(hello.vector(1).data)

    if hello.pos >= len(hello.data):
        return ch  # SSLv3-style hello with no extensions
    exts = hello.vector(2)
    while exts.pos < len(exts.data):
        code = exts.uint(2)
        value = exts.vector(2).data
        ch.extensions.append((code, value))
        if code == EXT_SNI:
            ch.sni = _parse_sni(value)
        elif code == EXT_ALPN:
            ch.alpn = _parse_alpn(value)
        elif code == EXT_SUPPORTED_GROUPS:
            ch.supported_groups = _parse_uint16_list(value)
        elif code == EXT_EC_POINT_FORMATS:
            v = _Reader(value)
            ch.ec_point_formats = list(v.vector(1).data)
        elif code == EXT_SIG_ALGS:
            ch.signature_algorithms = _parse_uint16_list(value)
        elif code == EXT_SUPPORTED_VERSIONS:
            versions = _Reader(value).vector(1)  # uint8 length, then versions
            ch.supported_versions = [int.from_bytes(versions.data[i : i + 2], "big")
                                     for i in range(0, len(versions.data), 2)]
    return ch


def _is_ssl_plaintext(data: bytes) -> bool:
    return len(data) >= 1 and data[0] == HANDSHAKE_TYPE


def read_client_hello(sock: socket.socket, timeout: float = 10.0) -> ClientHello:
    """Peek bytes off `sock` (without consuming them) until a ClientHello parses.

    Peeking keeps the bytes available for the real TLS handshake afterwards,
    which is what lets the echo server both fingerprint and serve the request.
    """
    sock.settimeout(timeout)
    size = 4096
    while size <= 262144:
        try:
            chunk = sock.recv(size, socket.MSG_PEEK)
        except (socket.timeout, TimeoutError) as exc:
            raise ClientHelloError("timed out waiting for the ClientHello") from exc
        if not chunk:
            raise ClientHelloError("connection closed before the ClientHello")
        if not _is_ssl_plaintext(chunk):
            raise ClientHelloError("not a TLS connection (no handshake record)")
        try:
            return parse_client_hello(chunk)
        except ClientHelloError:
            size *= 2  # probably fragmented: wait for more bytes to arrive
    raise ClientHelloError("ClientHello too large")
