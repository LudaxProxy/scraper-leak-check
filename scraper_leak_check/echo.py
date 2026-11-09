"""The echo server: what a website's edge would see, reported back as JSON.

`serve` accepts a TLS connection, peeks the ClientHello (without consuming
it, so the handshake still completes), computes the JA3/JA4 fingerprints,
reads the HTTP request and answers it with a JSON document describing:

  * the network view: source IP and port
  * the TLS view: JA4 (+ raw lists), JA3, version, SNI, ALPN, ciphers
  * the HTTP view: method, HTTP version, headers in the order sent,
    cookie count and primary language

Everything a fingerprinting WAF measures on the first request — which is
exactly what a scraper wants to check, through its own proxy chain.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .clienthello import ClientHelloError, read_client_hello
from .fingerprints import summary

_CERT = os.path.join(os.path.dirname(__file__), "dev-cert.pem")
_KEY = os.path.join(os.path.dirname(__file__), "dev-key.pem")
MAX_BODY = 64 * 1024


class _EchoTLSServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, addr, context: ssl.SSLContext, extra: dict | None = None):
        self.ssl_context = context
        self.extra = extra or {}
        self.last_request: dict = {}
        self._lock = threading.Lock()
        super().__init__(addr, _EchoHandler)

    def get_request(self):
        """Fingerprint the ClientHello before handing the socket to http.server."""
        sock, addr = super().get_request()
        try:
            hello = read_client_hello(sock)
            info = summary(hello)
        except ClientHelloError as exc:
            info = {"error": f"{exc}"}
        sock = self.ssl_context.wrap_socket(sock, server_side=True)
        sock.fingerprint = info  # type: ignore[attr-defined]
        return sock, addr

    def remember(self, data: dict) -> None:
        with self._lock:
            self.last_request = data


class _EchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # quiet by default
        pass

    def _payload(self) -> dict:
        tls = getattr(self.request, "fingerprint", {})
        headers = [[k.lower(), v] for k, v in self.headers.items() if k.lower() != "cookie"]
        cookies: list[list[str]] = []
        for raw in self.headers.get_all("Cookie", []) or []:
            for pair in raw.split(";"):
                name, _, value = pair.strip().partition("=")
                if name:
                    cookies.append([name, value])
        payload = {
            "ip": self.client_address[0],
            "port": self.client_address[1],
            "method": self.command,
            "http_version": self.request_version,
            "path": self.path,
            "headers": headers,
            "cookies": cookies,
            "tls": tls,
            "server": {
                "name": "scraper-leak-check",
                "note": "echo certificate is self-signed by design; "
                        "you are fingerprinting, not authenticating",
            },
        }
        payload.update(self.server.extra)  # type: ignore[attr-defined]
        return payload

    def _answer(self) -> None:
        payload = self._payload()
        self.server.remember(payload)  # type: ignore[attr-defined]
        body = json.dumps(payload, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._answer()

    do_POST = do_GET
    do_HEAD = do_GET


def make_server(
    host: str = "127.0.0.1",
    port: int = 0,
    certfile: str | None = None,
    keyfile: str | None = None,
    extra: dict | None = None,
) -> _EchoTLSServer:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile or _CERT, keyfile or _KEY)
    return _EchoTLSServer((host, port), context, extra)


def serve(
    host: str = "0.0.0.0",
    port: int = 8443,
    certfile: str | None = None,
    keyfile: str | None = None,
) -> None:
    """Run the echo server in the foreground (for public deployment)."""
    httpd = make_server(host, port, certfile, keyfile)
    print(f"scraper-leak-check echo server on https://{host}:{port}/ "
          "(self-signed cert unless --cert/--key given)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
