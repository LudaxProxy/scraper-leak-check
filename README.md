# scraper-leak-check

See your scraper the way a fingerprinting WAF sees it — **before** it answers.

One command shows the IP, the **JA4 / JA3 TLS fingerprints**, the HTTP
version and the headers **your client actually sends**, optionally **through
your proxy chain**. Everything an anti-bot system measures on the very first
request, reported back to you as JSON.

```console
$ leak-check local

[python]
  ja4           t13i180900_85036bcba153_1f22a2ca17c4
  ja3           175fbe59103d7b6df37bc6598e7361bd
  tls           version 13, alpn none, 18 ciphers, 9 extensions
  headers       accept-encoding, host, user-agent, connection
  looks like    non-browser client (no ALPN: browsers always offer h2)

[curl]
  ja4           t13i3111h2_e8f1e7e78f70_8d633dac7124
  tls           version 13, alpn ['h2', 'http/1.1'], 31 ciphers, 11 extensions
  looks like    curl 7.87.0 (OpenSSL build, Git for Windows)
```

![Real leak-check local output: Python and curl side by side](docs/leak-check-local.png)

Two stock clients, two completely different fingerprints — that is the gap a
WAF scores. A real Chromium on the same machine measures
`t13i1515h2_8daaf6152771_…` (15 ciphers, 15 extensions, h2 first).

## Why this exists

Modern anti-bot systems judge a request at the **TLS handshake**, before any
HTML loads: the ClientHello's cipher list, extensions and their order are
hashed into fingerprints like [JA4](https://github.com/FoxIO-LLC/ja4), which
[Cloudflare uses across its Bot Management, WAF and DDoS
products](https://blog.cloudflare.com/ja4-signals). A Python script claims a
Chrome user-agent while presenting OpenSSL's handshake — a mismatch no header
can fix.

`scraper-leak-check` gives that measurement to the scraper:

- **local** — zero-setup: an echo server starts on 127.0.0.1 and the stock
  clients on your machine (Python urllib, curl) are probed side by side
- **remote** — probe a public echo **through your proxy**, the exact chain
  your crawler uses; the report is what the target's edge sees
- **serve** — run the public echo yourself on any VPS

Pure Python stdlib. No dependencies, no virtualenv gymnastics.

## Install

```bash
pipx run --spec git+https://github.com/LudaxProxy/scraper-leak-check leak-check local
```

or from a checkout:

```bash
pip install -e .
leak-check local
```

## Usage

### 1. See what your machine's stock clients look like (zero setup)

```bash
leak-check local                 # probes python + curl
leak-check local --json          # machine-readable
```

### 2. See what your scraper + proxy chain looks like

Run an echo server anywhere public (the same package serves it):

```bash
# on your VPS
leak-check serve --port 8443 --cert fullchain.pem --key privkey.pem
```

Then, from the machine (and through the proxy) you want to test:

```bash
leak-check remote https://your-echo.example.com/ \
    --proxy "http://resi-USER:PASS-country-us@gw.ludaxproxy.com:7777"
```

A one-line exit check that works with any HTTP client, no tool needed:
[api.ludaxproxy.com/whoami](https://api.ludaxproxy.com/whoami) answers with the
IP, country and IP type the destination sees.

```bash
curl -x "http://resi-USER:PASS-country-us@gw.ludaxproxy.com:7777" https://api.ludaxproxy.com/whoami
```

Add `?full=1` and the same endpoint reports what a fingerprinting edge
measures: your `ja4`, the ClientHello extension order, the HTTP/2 fingerprint,
ALPN, HTTP version and ASN — plus `tls_profile`, the browser your handshake
claims to be. It is matched against 139 calibrated browser profiles by TLS key,
extension order and HTTP/2 fingerprint; a mismatched handshake reads `null`,
and no user-agent can change that:

```bash
curl "https://api.ludaxproxy.com/whoami?full=1"
```

Through a Ludax TLS plan the same call reports the profile you pinned, because
the gateway presents that browser's handshake downstream.

### 3. Why the proxy type decides what the target sees

A CONNECT proxy tunnels your TLS handshake through untouched, so the target
still reads *your* client's fingerprint. A TLS emulation gateway opens the
connection itself and presents a real browser’s handshake:

![Why a CONNECT proxy leaves your JA4 fingerprint alone but a TLS gateway replaces it](docs/proxy-paths.png)

The report shows the **exit IP** and the fingerprint **as presented after the
proxy** — for a CONNECT/HTTPS proxy the handshake is yours, passed through
untouched; for a TLS emulation gateway it is the browser profile's. Both
are exactly what you want to know.

With [Ludax Proxy](https://ludaxproxy.com) Residential TLS the username picks
the browser profile presented downstream, so the same probe measures the
profile you configured:

```bash
leak-check remote https://your-echo.example.com/ \
    --proxy "http://resi-user-AE-chrome154:pass-country-us@gw.ludaxproxy.com:9999"
```

### 4. Read the report

| Field | What it tells you |
| --- | --- |
| `ja4` | The TLS client fingerprint WAFs match on (see the [JA4 spec](https://github.com/FoxIO-LLC/ja4)) |
| `ja4_raw` | The raw sorted lists behind the hash, for comparing two clients |
| `ja3` | The classic fingerprint, for older rules and databases |
| `ip` | The address the target sees — your exit, after the proxy |
| `alpn`, `sni` | Protocol hints; browsers offer `h2`, scripts often offer nothing |
| `headers` | Your header set, **in the order sent** — order is itself a signal |
| `cookies` | Count carried on the first request (browsers on a first visit: 0, but see the cookie header) |

The `looks like` line compares against a small list of fingerprints measured
with this tool itself (`scraper_leak_check/known.py` — send a PR with yours),
plus cautious structural hints. For serious lookups, search the hash in the
public [JA4 databases](https://ja4db.com).

## How it works

The echo server accepts a TCP connection and **peeks** the ClientHello
without consuming it (`MSG_PEEK`), computes JA4/JA3 per the public
specification, then completes the TLS handshake and answers the HTTP request
with the report as JSON. Nothing is stored, nothing is forwarded; the bundled
certificate is self-signed on purpose — you are fingerprinting, not
authenticating.

JA4 itself is an open format (BSD 3-Clause) by [FoxIO](https://foxio.io);
this project implements it from the specification text and carries no
FoxIO code.

## Verification

- 20 tests: spec-derived unit vectors (independent of the production code),
  integration through a local CONNECT proxy, and CLI end-to-end
- Cross-checked against an external fingerprinting service: the JA4 this
  tool reports for `curl 7.87.0` is byte-identical to the one
  `tls.browserleaks.com` reports for the same binary
  (`t13d3112h2_e8f1e7e78f70_8d633dac7124`, 2026-11-08)
- A real Chromium measured by this tool produces the cipher-section hash
  `8daaf6152771` — the same hash used in the worked example of the official
  JA4 specification
- [api.ludaxproxy.com/whoami?full=1](https://api.ludaxproxy.com/whoami?full=1)
  independently reports the same JA4 for the same curl — a third source
  agreeing, after the tool itself and tls.browserleaks.com

```bash
python -m pytest
```

## Contributing

Measured a fingerprint worth knowing (a browser build, a library, an
antidetect browser)? Add it to `known.py` or `tests/data/` with how you
measured it, and open a PR. Domain-heavy blocklist-style contributions are
welcome too — see our [scraping-blocklist](https://github.com/LudaxProxy/scraping-blocklist).

## License

MIT — see [LICENSE](LICENSE). JA4® is a trademark of FoxIO, LLC; this
project is not affiliated with FoxIO.

---

By [Ludax Proxy](https://ludaxproxy.com) — residential proxies with real
browser TLS profiles. If this tool told you your fingerprint is the problem,
that is exactly what we sell the fix for: [Residential TLS
Proxies](https://ludaxproxy.com/products/residential-tls-proxies).
