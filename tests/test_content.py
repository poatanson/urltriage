"""--deep HTML 분석 테스트.

픽스처는 탐지 로직 검증용 최소 HTML 문자열이다. 서버/수집 로직이 없고,
폼 action 은 RFC 2606 예약 도메인(.example)만 사용한다.
"""

import asyncio

import httpx
import pytest

from urltriage.checks.content import analyze_html, check_content, favicon_sha256
from urltriage.checks.typosquat import Brand, load_brands
from urltriage.models import Status
from urltriage.urlutils import parse_url

BRANDS = load_brands()


def analyze(html, url="https://site.example/login"):
    r, _ = analyze_html(html, url, BRANDS)
    return r.finalize()


def messages(r):
    return " | ".join(f.message for f in r.findings)


def test_plain_page_clean():
    r = analyze("<html><head><title>Hello</title></head><body><p>hi</p></body></html>")
    assert r.risk == 0 and r.data["password_forms"] == 0


def test_same_domain_login_form_low_risk():
    r = analyze('<form action="/session" method="post"><input name="u"><input type="password" name="p"></form>')
    assert r.data["password_forms"] == 1
    assert r.risk == pytest.approx(0.15)


def test_password_form_to_external_domain():
    r = analyze('<form action="https://collector.example.net/x"><input type="PASSWORD"></form>')
    assert "외부 도메인(example.net)" in messages(r)
    assert r.risk >= 0.8


def test_non_password_form_external_is_mild():
    r = analyze('<form action="https://search.other.example.org/q"><input name="q"></form>')
    assert r.risk == pytest.approx(0.15)


def test_mailto_form():
    r = analyze('<form action="mailto:someone@site.example"><input type="password"></form>')
    assert "mailto" in messages(r)


def test_https_page_posting_to_http():
    r = analyze('<form action="http://site.example/session"><input type="password"></form>')
    assert "평문 HTTP" in messages(r)


def test_favicon_hotlinked_from_brand():
    r = analyze('<link rel="shortcut icon" href="https://www.paypalobjects.com/favicon.ico">')
    assert "paypal" in messages(r) and r.risk >= 0.7


def test_favicon_on_official_site_not_flagged():
    r, _ = analyze_html('<link rel="icon" href="https://www.paypalobjects.com/favicon.ico">'
                        '<form action="/signin"><input type="password"></form>',
                        "https://www.paypal.com/signin", BRANDS)
    assert r.finalize().risk == 0


def test_brand_in_title_on_unofficial_domain():
    r = analyze("<title>Naver 로그인</title>")
    assert "naver" in messages(r)


def test_cross_brand_official_action_is_same_owner():
    # kakao.com 페이지가 kakao 공식 도메인(daum.net)으로 전송 → 외부 전송 아님
    r, _ = analyze_html('<form action="https://logins.daum.net/x"><input type="password"></form>',
                        "https://accounts.kakao.com/login", BRANDS)
    assert "외부 도메인" not in messages(r.finalize())


def test_favicon_hash_match_via_check_content():
    icon = b"\x00\x00\x01\x00fake-icon-bytes"
    brands = [Brand("examplebrand", ("examplebrand.com",), (favicon_sha256(icon),))]

    def handler(req: httpx.Request):
        if req.url.path == "/favicon.ico":
            return httpx.Response(200, content=icon, headers={"content-type": "image/x-icon"})
        return httpx.Response(200, text="<html><title>t</title></html>", headers={"content-type": "text/html"})

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await check_content(parse_url("https://lookalike.example"), "https://lookalike.example/",
                                       brands, 5, c)
    r = asyncio.run(go())
    assert "SHA-256 일치" in messages(r) and r.risk >= 0.8


def test_non_html_is_skipped():
    def handler(req):
        return httpx.Response(200, content=b"%PDF", headers={"content-type": "application/pdf"})

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await check_content(parse_url("https://a.example"), "https://a.example/", BRANDS, 5, c)
    assert asyncio.run(go()).status is Status.SKIPPED
