"""Integration: the echo server end to end, including through an HTTP proxy.

A miniature CONNECT proxy runs inside the test: the client asks it to
tunnel to the echo server, the proxy opens the TCP connection and pipes
bytes both ways. TLS passes through untouched, so the echo server must
see the client's own ClientHello — the same property real HTTPS proxies
have, and the reason a proxy cannot change your TLS fingerprint.
"""
import json
import socket
import ssl
import threading
import urllib.request

import pytest

from scraper_leak_check.cli import main as cli_main
from scraper_leak_check.clients import probe_python
from scraper_leak_check.echo import make_server


@pytest.fixture()
def echo():
    server = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture()
def echo_url(echo):
    return f"https://127.0.0.1:{echo.server_address[1]}/"


class MiniConnectProxy:
    """A tiny HTTP proxy that only implements CONNECT, for the test."""

    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def close(self):
        self.listener.close()

    def _loop(self):
        while True:
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client):
        upstream = None
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = client.recv(4096)
                if not chunk:
                    return
                data += chunk
            line = data.split(b"\r\n", 1)[0].decode("latin-1")
            parts = line.split()
            if len(parts) < 2 or parts[0] != "CONNECT":
                client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
                return
            host, port = parts[1].rsplit(":", 1)
            upstream = socket.create_connection((host, int(port)), timeout=10)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            import select

            pair = [client, upstream]
            while True:
                readable, _, _ = select.select(pair, [], [], 20)
                if not readable:
                    return  # idle: let the test finish
                for source in readable:
                    blob = source.recv(65536)
                    if not blob:
                        return
                    (upstream if source is client else client).sendall(blob)
        except OSError:
            pass
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass


def test_python_probe_gets_full_report(echo, echo_url):
    info = probe_python(echo_url)
    tls = info["tls"]
    assert info["method"] == "GET"
    assert info["ip"] == "127.0.0.1"
    assert tls["ja4"].startswith("t1") and len(tls["ja4"].split("_")) == 3
    assert len(tls["ja3"]) == 32
    assert "user-agent" in [k for k, _ in info["headers"]]
    assert tls["sni"] == "127.0.0.1" or tls["sni"] is None


def test_fingerprint_is_stable(echo, echo_url):
    first = probe_python(echo_url)["tls"]["ja4"]
    second = probe_python(echo_url)["tls"]["ja4"]
    assert first == second


def test_raw_ssl_socket_reported(echo):
    port = echo.server_address[1]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as tls_sock:
            tls_sock.sendall(b"GET /raw HTTP/1.1\r\nHost: localhost\r\nUser-Agent: raw\r\nAccept: */*\r\nConnection: close\r\n\r\n")
            body = b""
            while chunk := tls_sock.recv(65536):
                body += chunk
    payload = json.loads(body.split(b"\r\n\r\n", 1)[1])
    assert payload["method"] == "GET"
    assert payload["tls"]["ja4"]
    assert payload["headers"][0] == ["host", "localhost"]  # order preserved


def test_probe_through_connect_proxy_unchanged(echo, echo_url):
    direct = probe_python(echo_url)["tls"]["ja4"]
    proxy = MiniConnectProxy().start()
    try:
        handler = urllib.request.ProxyHandler({"https": f"http://127.0.0.1:{proxy.port}"})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        opener = urllib.request.build_opener(handler, urllib.request.HTTPSHandler(context=ctx))
        with opener.open(echo_url, timeout=20) as response:
            via_proxy = json.loads(response.read().decode())["tls"]["ja4"]
    finally:
        proxy.close()
    assert via_proxy == direct  # a CONNECT proxy passes the handshake through


def test_cli_local_json(echo, capsys):
    code = cli_main(["local", "--client", "python", "--json"])
    out = capsys.readouterr().out
    assert code == 0
    data = json.loads(out)
    assert "python" in data
    assert data["python"]["tls"]["ja4"]
