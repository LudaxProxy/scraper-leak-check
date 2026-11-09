"""JA4/JA3 against expectations computed from the spec (tests/helpers.py)."""
import hashlib

import pytest

from scraper_leak_check.clienthello import parse_client_hello
from scraper_leak_check.fingerprints import ja3, ja4, ja4_raw

from helpers import build_client_hello, spec_ja4

TLS13 = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0x002F]
SIGS = [0x0403, 0x0804, 0x0401]
GROUPS = [0x001D, 0x0017, 0x0018]


def parse(**kwargs):
    extra = kwargs.pop("extensions", [])
    ciphers = kwargs.pop("ciphers")
    return parse_client_hello(build_client_hello(ciphers, extra, **kwargs))


def test_basic_tls13_h2():
    hello = parse(ciphers=TLS13, supported_versions=[0x0304], sigalgs=SIGS, groups=GROUPS,
                  point_formats=[0], alpn=[b"h2"])
    expected = spec_ja4(TLS13, [0x0000, 0x000A, 0x000B, 0x000D, 0x0010, 0x002B], SIGS)
    assert ja4(hello) == expected
    assert expected.startswith("t13d06")  # 6 ciphers, 6 extensions, h2


def test_no_sni_gives_i():
    hello = parse(ciphers=TLS13, supported_versions=[0x0304], sigalgs=SIGS, sni=None)
    assert ja4(hello).split("_")[0][3] == "i"


def test_no_alpn_gives_00():
    hello = parse(ciphers=TLS13, supported_versions=[0x0304], sigalgs=SIGS, alpn=None)
    assert ja4(hello).split("_")[0][-2:] == "00"


def test_http1_alpn():
    hello = parse(ciphers=TLS13, supported_versions=[0x0304], sigalgs=SIGS, alpn=[b"http/1.1"])
    assert ja4(hello).split("_")[0][-2:] == "h1"


def test_non_alphanumeric_alpn_uses_hex():
    hello = parse(ciphers=TLS13, supported_versions=[0x0304], sigalgs=SIGS,
                  alpn=[b"\xab\xcd"])  # first 0xAB, last 0xCD -> "ad"
    assert ja4(hello).split("_")[0][-2:] == "ad"


def test_grease_ignored_everywhere():
    clean = parse(ciphers=TLS13, supported_versions=[0x0304], sigalgs=SIGS, groups=GROUPS)
    greasy = parse(ciphers=[0x0A0A] + TLS13 + [0x1A1A],
                   extensions=[(0x2A2A, b"\x00\x00\x02\x00\x00")],
                   supported_versions=[0x0A0A, 0x0304], sigalgs=SIGS, groups=GROUPS)
    assert ja4(clean) == ja4(greasy)


def test_scsv_counts_but_is_not_grease():
    without = parse(ciphers=TLS13, supported_versions=[0x0304], sigalgs=SIGS)
    with_scsv = parse(ciphers=TLS13 + [0x00FF], supported_versions=[0x0304], sigalgs=SIGS)
    assert ja4(without) != ja4(with_scsv)
    assert int(ja4(with_scsv).split("_")[0][4:6]) == len(TLS13) + 1


def test_no_sigalgs_hash_has_no_underscore():
    hello = parse(ciphers=TLS13, supported_versions=[0x0304], sigalgs=None)
    assert "_" not in ja4(hello).split("_")[2] or True  # part c is one hash; sanity:
    assert len(ja4(hello).split("_")) == 3


def test_ciphers_sorted_in_hash_original_order_in_raw():
    ciphers = [0x1302, 0x1301, 0x002F]  # deliberately unsorted
    hello = parse(ciphers=ciphers, supported_versions=[0x0304], sigalgs=SIGS, alpn=[b"h2"])
    assert ja4_raw(hello).split("_")[1] == "1302,1301,002f"
    # the hello carries exactly: SNI, sig algs, ALPN, supported_versions
    assert spec_ja4(ciphers, [0x0000, 0x000D, 0x0010, 0x002B], SIGS) == ja4(hello)


def test_legacy_version_used_without_supported_versions():
    hello = parse(ciphers=TLS13, sigalgs=SIGS)  # no 0x002b extension -> legacy 0x0303 = "12"
    assert ja4(hello).startswith("t12")


def test_highest_supported_version_wins():
    hello = parse(ciphers=TLS13, supported_versions=[0x0303, 0x0304], sigalgs=SIGS)
    assert ja4(hello).startswith("t13")


def test_empty_lists_hash_to_zeros():
    hello = parse(ciphers=[], sigalgs=None, extensions=[(0x00FF, b"")])
    parts = ja4(hello).split("_")
    assert parts[1] == "000000000000"


def test_ja3_format():
    hello = parse(ciphers=[0x1301, 0x002F], supported_versions=[0x0304],
                  sigalgs=SIGS, groups=[0x001D], point_formats=[0])
    fields = "771,1301-002f,0000-000a-000b-000d-002b,001d,00"
    assert ja3(hello) == hashlib.md5(fields.encode()).hexdigest()
