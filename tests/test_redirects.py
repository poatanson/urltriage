import asyncio

import httpx
import pytest

from urltriage.checks.redirects import MAX_HOPS, check_redirects
from urltriage.checks.typosquat import load_brands
from urltriage.models import Status
from urltriage.urlutils import parse_url

BRANDS = load_brands()


def client_for(routes: dict[str, tuple[int, str | None]]):
    """routes: url -> (status, location). 정의되지 않은 URL은 200."""
    def handler(request: httpx.Request):
        status, loc = routes.get(str(request.url), (200, None))
        return httpx.Response(status, headers={"location": loc} if loc else {})
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)


def run(url, routes):
    async def go():
        async with client_for(routes) as c:
            return await check_redirects(parse_url(url), BRANDS, 5, client=c)
    return asyncio.run(go())


def test_no_redirect():
    r = run("https://example.com/", {})
    assert r.status is Status.OK and r.risk == 0 and r.data["hops"] == 0


def test_same_domain_redirect_is_fine():
    r = run("http://example.com/", {"http://example.com/": (301, "https://www.example.com/")})
    assert r.risk == 0 and r.data["hops"] == 1


def test_cross_domain_redirect_flagged():
    r = run("https://example.com/", {"https://example.com/": (302, "https://other.example.net/")})
    assert r.risk == pytest.approx(0.4)
    assert r.data["final_registered_domain"] == "example.net"


def test_shortener_to_lookalike_is_high_risk():
    r = run("https://bit.ly/abc", {"https://bit.ly/abc": (301, "https://paypa1.com/login")})
    msgs = " ".join(f.message for f in r.findings)
    assert "사칭" in msgs and r.risk >= 0.9


def test_relative_location_and_many_hops():
    routes = {f"https://example.com/{i}": (302, f"/{i + 1}") for i in range(6)}
    r = run("https://example.com/0", routes)
    assert r.data["hops"] == 6 and "과다" in r.findings[0].message


def test_redirect_loop_capped():
    r = run("https://example.com/a", {"https://example.com/a": (302, "https://example.com/a")})
    assert len(r.data["chain"]) == MAX_HOPS + 1
    assert any("초과" in f.message for f in r.findings)


def test_https_downgrade():
    r = run("https://example.com/", {"https://example.com/": (301, "http://example.com/")})
    assert any("다운그레이드" in f.message for f in r.findings)


def test_brand_official_cross_domain_not_flagged():
    r = run("https://www.kakao.com/", {"https://www.kakao.com/": (302, "https://www.daum.net/")})
    assert r.risk == 0


def test_connection_error_unavailable():
    def handler(request):
        raise httpx.ConnectError("boom")
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await check_redirects(parse_url("https://example.com"), BRANDS, 5, client=c)
    assert asyncio.run(go()).status is Status.UNAVAILABLE


@pytest.mark.network
def test_bitly_root_live():
    async def go():
        return await check_redirects(parse_url("https://bit.ly"), BRANDS, 5)
    r = asyncio.run(go())
    assert r.status is Status.OK and r.data["hops"] >= 1 and r.data["final_registered_domain"] == "bitly.com"
