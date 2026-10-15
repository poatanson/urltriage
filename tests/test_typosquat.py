import json

import pytest

from urltriage.checks.typosquat import (
    check_typosquat, homoglyph_variants, levenshtein, load_brands, osa_distance,
)
from urltriage.urlutils import parse_url

BRANDS = load_brands()


def check(url):
    return check_typosquat(parse_url(url), BRANDS)


@pytest.mark.parametrize("a,b,lev", [
    ("google", "google", 0), ("gooogle", "google", 1), ("paypa1", "paypal", 1),
    ("goolge", "google", 2), ("kitten", "sitting", 3), ("", "abc", 3),
])
def test_levenshtein(a, b, lev):
    assert levenshtein(a, b) == lev
    assert levenshtein(b, a) == lev


def test_osa_counts_transposition_once():
    assert osa_distance("goolge", "google") == 1
    assert osa_distance("naevr", "naver") == 1


def test_homoglyphs():
    assert "google" in homoglyph_variants("g00gle")
    assert "paypal" in homoglyph_variants("paypa1")
    assert "microsoft" in homoglyph_variants("rnicrosoft")
    assert "apple" in homoglyph_variants("xn--pple-43d")  # 키릴 'а'


@pytest.mark.parametrize("url", ["google.com", "https://mail.google.com/x", "naver.com", "www.kakao.com", "paypal.me"])
def test_official_domains_are_safe(url):
    r = check(url)
    assert r.risk == 0.0 and r.data["official_brand"]


@pytest.mark.parametrize("url,brand,min_risk", [
    ("gooogle.com", "google", 0.9),
    ("paypa1.com", "paypal", 1.0),
    ("goolge.com", "google", 0.9),
    ("g00gle-login.tk", "google", 0.85),
    ("xn--pple-43d.com", "apple", 1.0),
    ("paypal.com.secure-check.tk", "paypal", 0.85),
    ("kakao-pay-event.xyz", "kakao", 0.85),
    ("google.tk", "google", 0.7),
])
def test_lookalikes_detected(url, brand, min_risk):
    r = check(url)
    assert r.risk >= min_risk
    assert r.data["matched_brand"] == brand


@pytest.mark.parametrize("url", ["pineapple.com", "example.com", "wikipedia.org", "bank.com"])
def test_unrelated_domains_not_flagged(url):
    assert check(url).risk == 0.0


def test_ip_host_checks_only_userinfo_and_path():
    assert check("http://10.0.0.1/").risk == 0.0
    assert check("http://10.0.0.1/kakao/login").risk == pytest.approx(0.3)


def test_brand_in_userinfo():
    r = check("https://www.paypal.com@secure-check.tk/signin")
    assert r.risk == 0.85 and r.data["matched_brand"] == "paypal"


def test_official_domain_boundary():
    assert check("https://paypal.com.evil.tk/").risk == 0.85
    assert "공식 도메인" not in " ".join(f.message for f in check("https://mypaypal.com.evil.tk/").findings)


def test_custom_brand_file(tmp_path):
    f = tmp_path / "b.json"
    f.write_text(json.dumps({"brands": [{"name": "examplebank", "domains": ["examplebank.com"]}]}), encoding="utf-8")
    r = check_typosquat(parse_url("examp1ebank.com"), load_brands(f))
    assert r.risk == 1.0 and r.data["matched_brand"] == "examplebank"
