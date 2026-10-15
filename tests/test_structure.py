import pytest

from urltriage.checks.structure import check_structure
from urltriage.urlutils import parse_url


def msgs(url: str) -> str:
    return " | ".join(f.message for f in check_structure(parse_url(url)).findings)


def risk(url: str) -> float:
    return check_structure(parse_url(url)).risk


def test_clean_url_has_no_findings():
    assert risk("https://www.google.com") == 0.0
    assert risk("naver.com") == 0.0


@pytest.mark.parametrize("url", ["http://192.168.10.5/", "http://3232235777/", "http://0xC0.0xA8.0.1/", "http://[::1]/"])
def test_ip_host(url):
    assert "IP 주소" in msgs(url)


def test_at_sign_userinfo():
    m = msgs("https://www.paypal.com@evil-host.tk/signin")
    assert "'@'" in m and "evil-host.tk" in m


def test_subdomain_depth():
    assert "과도한 서브도메인" in msgs("https://a.b.c.d.example.com/")
    assert "서브도메인" not in msgs("https://mail.example.com/")


def test_hyphens_and_tld():
    m = msgs("https://pay-pal-secure-account.xyz/")
    assert "하이픈 과다" in m and ".xyz" in m


def test_punycode_delimiter_not_counted_as_hyphen():
    m = msgs("https://xn--pple-43d.com")
    assert "퓨니코드" in m and "하이픈" not in m


def test_nonstandard_port():
    assert "비표준 포트" in msgs("https://example.com:8443/")
    assert "비표준 포트" not in msgs("https://example.com:443/")


def test_url_length():
    assert "URL 길이 과다" in msgs("https://example.com/" + "a" * 120)


def test_risk_is_capped():
    assert risk("http://user@192.168.0.1:8080/a.b.login//verify-account-secure?x=" + "a" * 100) == 1.0
