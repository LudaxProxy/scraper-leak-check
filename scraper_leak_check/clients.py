"""Local HTTP clients the `local` command probes with.

The point: every stock HTTP stack has its own TLS ClientHello, and the
echo server shows them side by side. `python` is the stdlib client every
scraper starts with; `curl` is probed when the system has one.
"""
from __future__ import annotations

import json
import shutil
import ssl
import subprocess
import urllib.request


def probe_python(url: str) -> dict:
    """GET `url` with urllib and return the echo JSON."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(url, context=ctx, timeout=15) as response:
        return json.loads(response.read().decode())


def probe_curl(url: str) -> dict:
    """GET `url` with the system curl (http2 allowed) and return the echo JSON."""
    binary = shutil.which("curl")
    if not binary:
        raise FileNotFoundError("curl not found on PATH")
    out = subprocess.run(
        [binary, "-sS", "--max-time", "20", "-k", url],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return json.loads(out)


PROBES = {"python": probe_python, "curl": probe_curl}
