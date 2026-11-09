"""Golden reference test against tls.browserleaks.com data (offline).

On 2026-11-08, Python 3.14's stdlib client (urllib, `ssl.create_default_context`)
was pointed at tls.browserleaks.com, which reported the JA4 and the raw lists
below (tests/data/crosscheck_browserleaks.json). Rebuilding a ClientHello from
those exact lists and running it through scraper_leak_check must reproduce
their published JA4 character for character — an external check that the
algorithm (version pick, counts, SNI/ALPN handling, sorting, exclusions,
truncated sha256) matches the real world, not just our own reading of the spec.
"""
import json
import os

from scraper_leak_check.clienthello import parse_client_hello
from scraper_leak_check.fingerprints import ja4

from helpers import build_client_hello

HERE = os.path.dirname(__file__)
REFERENCE = json.loads(open(os.path.join(HERE, "data", "crosscheck_browserleaks.json")).read())


def _lists_from_reference():
    head, ciphers, rest = REFERENCE["ja4_r"].split("_", 2)
    extensions, _, sigalgs = rest.partition("_")
    to_ints = lambda part: [int(x, 16) for x in part.split(",")] if part else []
    return to_ints(ciphers), to_ints(extensions), to_ints(sigalgs), head


def test_reference_ja4_reproduced_from_published_lists():
    ciphers, extensions, sigalgs, head = _lists_from_reference()
    assert head == REFERENCE["ja4"].split("_")[0]  # counts agree with the raw lists

    # Rebuild the hello: SNI added by the builder, real values for the
    # extensions the fingerprint needs to see (0x000d, 0x002b), opaque
    # placeholders for the rest. No ALPN (head ends '00').
    others = [(code, b"\x00\x00") for code in extensions
              if code not in (0x000D, 0x002B)]
    synthetic = build_client_hello(
        ciphers,
        others,
        supported_versions=[0x0303, 0x0304],
        sigalgs=sigalgs,
        alpn=None,
        sni=b"tls.browserleaks.com",
    )
    assert ja4(parse_client_hello(synthetic)) == REFERENCE["ja4"]


def test_reference_head_fields():
    head = REFERENCE["ja4"].split("_")[0]
    ciphers, extensions, sigalgs, _ = _lists_from_reference()
    assert head[0] == "t"  # TLS over TCP
    assert head[1:3] == "13"  # TLS 1.3 via supported_versions
    assert head[3] == "d"  # SNI present
    assert int(head[4:6]) == len(ciphers)  # cipher count (SCSV 00ff counted)
    assert int(head[6:8]) == len(extensions) + 1  # + the SNI extension itself
    assert head[8:10] == "00"  # no ALPN offered
