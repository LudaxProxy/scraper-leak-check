"""`leak-check`: what does your request look like to the site you scrape?

Three commands:

  local    start an echo server on 127.0.0.1 and probe it with the local
           stock clients (python urllib, curl if present) — zero setup
  remote   probe a public echo server, optionally through a proxy:
           this is the one that shows what your scraper + proxy chain sends
  serve    run the public echo server yourself (any VPS)

Output is human-readable by default, JSON with --json.
"""
from __future__ import annotations

import argparse
import json
import ssl
import sys
import threading
import urllib.request

from . import __version__
from .clients import PROBES
from .echo import make_server, serve
from .known import label_for, structural_hint


def _render(info: dict) -> str:
    tls = info.get("tls", {})
    lines = [
        f"  ip            {info.get('ip')}:{info.get('port')}",
        f"  method        {info.get('method')} {info.get('path')} "
        f"({info.get('http_version')})",
    ]
    if "error" in tls:
        lines.append(f"  tls           ERROR: {tls['error']}")
        return "\n".join(lines)
    header_names = ", ".join(k for k, _ in info.get("headers", []))
    lines += [
        f"  ja4           {tls.get('ja4')}",
        f"  ja4 (raw)     {str(tls.get('ja4_raw'))[:96]}…",
        f"  ja3           {tls.get('ja3')}",
        f"  tls           version {tls.get('tls_version')}, alpn {tls.get('alpn') or 'none'}, "
        f"{tls.get('cipher_count')} ciphers, {tls.get('extension_count')} extensions",
        f"  sni           {tls.get('sni') or '(none)'}",
        f"  headers       {header_names or '(none)'}",
        f"  cookies       {len(info.get('cookies', []))}",
    ]
    known = label_for(tls.get("ja4", ""))
    hint = structural_hint(info)
    verdict = known or hint or "no match in the known list (that is normal for custom stacks)"
    lines.append(f"  looks like    {verdict}")
    return "\n".join(lines)


def cmd_local(args: argparse.Namespace) -> int:
    server = make_server("127.0.0.1", args.port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"https://127.0.0.1:{server.server_address[1]}/"
    names = ["python", "curl"] if args.client == "all" else [args.client]
    results: dict[str, dict] = {}
    blocks = []
    for name in names:
        try:
            info = PROBES[name](url)
        except Exception as exc:  # missing curl, refused connection
            blocks.append(f"[{name}] skipped: {exc}")
            continue
        results[name] = info
        blocks.append(f"[{name}]\n{_render(info)}")
    server.shutdown()
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("\n\n".join(blocks))
    return 0 if results else 1


def cmd_remote(args: argparse.Namespace) -> int:
    handlers = []
    if args.proxy:
        handlers.append(urllib.request.ProxyHandler({"https": args.proxy, "http": args.proxy}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))  # ignore env proxies
    opener = urllib.request.build_opener(*handlers)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    request = urllib.request.Request(args.url, headers={"User-Agent": args.user_agent})
    with opener.open(request, timeout=args.timeout) as response:
        info = json.loads(response.read().decode())
    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print(_render(info))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    serve(args.host, args.port, args.cert, args.key)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="leak-check",
        description="See the IP, JA4 TLS fingerprint and HTTP headers your "
                    "scraper sends — the way a fingerprinting WAF sees them.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_local = sub.add_parser("local", help="probe a local echo with stock clients")
    p_local.add_argument("--port", type=int, default=0)
    p_local.add_argument("--client", choices=["python", "curl", "all"], default="all")
    p_local.add_argument("--json", action="store_true")
    p_local.set_defaults(fn=cmd_local)

    p_remote = sub.add_parser("remote", help="probe a public echo server, optionally via a proxy")
    p_remote.add_argument("url", help="echo server URL, e.g. https://echo.example.com/")
    p_remote.add_argument("--proxy", help="http://user:pass@host:port — the chain to test")
    p_remote.add_argument("--user-agent", default="leak-check")
    p_remote.add_argument("--timeout", type=float, default=20)
    p_remote.add_argument("--json", action="store_true")
    p_remote.set_defaults(fn=cmd_remote)

    p_serve = sub.add_parser("serve", help="run the echo server (public deployment)")
    p_serve.add_argument("--host", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=8443)
    p_serve.add_argument("--cert", default=None, help="PEM cert for the echo (else bundled self-signed)")
    p_serve.add_argument("--key", default=None)
    p_serve.set_defaults(fn=cmd_serve)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
