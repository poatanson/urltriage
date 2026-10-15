import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from urltriage.checks import domain_age
from urltriage.checks.domain_age import _to_datetime, check_domain_age
from urltriage.checks.ssl_cert import check_ssl, hostname_matches
from urltriage.models import Status
from urltriage.urlutils import parse_url

NOW = datetime(2026, 10, 15, tzinfo=UTC)


def run(coro):
    return asyncio.run(coro)


# ----------------------------------------------------------------- 오프라인(mock) 테스트

def test_to_datetime_variants():
    assert _to_datetime([datetime(2020, 1, 2), datetime(2019, 5, 1)]) == datetime(2019, 5, 1, tzinfo=UTC)
    assert _to_datetime("1997-09-15T04:00:00Z") == datetime(1997, 9, 15, 4, tzinfo=UTC)
    assert _to_datetime(None) is None


def _fake_lookup(created):
    async def f(domain, timeout):
        return created, "mock", "Mock Registrar"
    return f


@pytest.mark.parametrize("days,risk", [(3, 1.0), (29, 1.0), (45, 0.6), (120, 0.4), (300, 0.2), (4000, 0.0)])
def test_age_bands(monkeypatch, days, risk):
    monkeypatch.setattr(domain_age, "_via_whois", _fake_lookup(NOW - timedelta(days=days)))
    r = run(check_domain_age(parse_url("example.com"), now=NOW))
    assert r.status is Status.OK and r.risk == risk


def test_whois_exception_falls_back_to_rdap(monkeypatch):
    async def boom(domain, timeout):
        raise ConnectionResetError("whois server reset")
    monkeypatch.setattr(domain_age, "_via_whois", boom)
    monkeypatch.setattr(domain_age, "_via_rdap", _fake_lookup(NOW - timedelta(days=10)))
    r = run(check_domain_age(parse_url("example.com"), now=NOW))
    assert r.status is Status.OK and r.risk == 1.0


def test_whois_timeout_marks_unavailable(monkeypatch):
    def slow(domain, timeout):
        import time
        time.sleep(0.5)
        return {}
    monkeypatch.setattr(domain_age, "_whois_lookup", slow)
    r = run(check_domain_age(parse_url("example.com"), timeout=0.05, use_rdap_fallback=False))
    assert r.status is Status.UNAVAILABLE
    assert "타임아웃" in r.reason and r.risk == 0.0


def test_all_lookups_fail_marks_unavailable(monkeypatch):
    async def fail(domain, timeout):
        raise LookupError("no data")
    monkeypatch.setattr(domain_age, "_via_whois", fail)
    monkeypatch.setattr(domain_age, "_via_rdap", fail)
    r = run(check_domain_age(parse_url("example.com")))
    assert r.status is Status.UNAVAILABLE and "no data" in r.reason


def test_missing_creation_date_is_unavailable(monkeypatch):
    monkeypatch.setattr(domain_age, "_via_whois", _fake_lookup(None))
    r = run(check_domain_age(parse_url("example.com"), use_rdap_fallback=False))
    assert r.status is Status.UNAVAILABLE and "생성일" in r.reason


def test_ip_is_skipped():
    assert run(check_domain_age(parse_url("http://10.1.2.3/"))).status is Status.SKIPPED


def test_hostname_matching():
    assert hostname_matches("www.google.com", ["*.google.com"])
    assert not hostname_matches("a.b.google.com", ["*.google.com"])
    assert not hostname_matches("google.com", ["*.google.com"])
    assert hostname_matches("google.com", ["google.com"])


def test_ssl_unresolvable_host_unavailable():
    a, b = run(check_ssl(parse_url("https://nonexistent-test.invalid"), timeout=3))
    assert a.status is Status.UNAVAILABLE and b.status is Status.UNAVAILABLE


# ----------------------------------------------------------------- 실제 네트워크

@pytest.mark.network
def test_google_whois_live():
    r = run(check_domain_age(parse_url("google.com")))
    assert r.status is Status.OK and r.data["age_days"] > 365 * 20 and r.risk == 0


@pytest.mark.network
def test_google_ssl_live():
    a, b = run(check_ssl(parse_url("https://google.com")))
    assert a.status is Status.OK and a.risk == 0 and a.data["hostname_match"]
    assert b.status is Status.OK


@pytest.mark.network
@pytest.mark.parametrize("host,min_risk", [("expired.badssl.com", 0.7), ("wrong.host.badssl.com", 0.9), ("self-signed.badssl.com", 0.8)])
def test_badssl_live(host, min_risk):
    a, _ = run(check_ssl(parse_url(f"https://{host}")))
    assert a.status is Status.OK and a.risk >= min_risk
