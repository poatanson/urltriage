"""HTML 콘텐츠 분석 (--deep 옵션일 때만).

페이지 HTML을 받아 '읽기만' 한다 (스크립트 실행·폼 제출 없음).
- 비밀번호 입력란이 있는 로그인 폼 존재 여부
- 폼 action이 외부 도메인 / mailto / 평문 http 로 전송되는지
- 파비콘을 브랜드 공식 도메인에서 직접 가져오거나, 파비콘 해시가 브랜드 공식 파비콘과 같은데
  페이지 도메인은 그 브랜드가 아닌 경우
- <title>에 브랜드명이 있는데 도메인은 공식이 아닌 경우
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from urltriage.checks.typosquat import Brand, official_brand_for
from urltriage.models import CheckResult
from urltriage.urlutils import parse_url, registered_domain_of

KEY = "content"
TITLE = "HTML 콘텐츠"

MAX_HTML_BYTES = 2 * 1024 * 1024
MAX_FAVICON_BYTES = 256 * 1024


@dataclass
class Fetched:
    url: str
    status_code: int
    content_type: str
    body: bytes
    encoding: str | None

    @property
    def text(self) -> str:
        return self.body.decode(self.encoding or "utf-8", errors="replace")


async def _get_limited(client: httpx.AsyncClient, url: str, limit: int, timeout: float) -> Fetched:
    """응답 본문을 limit 바이트까지만 읽는다 (거대한 응답 방지)."""
    req = client.build_request("GET", url, timeout=timeout)
    resp = await client.send(req, stream=True, follow_redirects=True)
    try:
        buf = bytearray()
        async for chunk in resp.aiter_bytes():
            buf += chunk
            if len(buf) >= limit:
                break
    finally:
        await resp.aclose()
    return Fetched(str(resp.url), resp.status_code, resp.headers.get("content-type", ""),
                   bytes(buf[:limit]), resp.charset_encoding)


def favicon_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _same_owner(a_rd: str, b_rd: str, brands: list[Brand]) -> bool:
    """같은 등록 도메인이거나 같은 브랜드의 공식 도메인들끼리인가."""
    if a_rd == b_rd:
        return True
    ba = official_brand_for(a_rd, brands)
    return ba is not None and ba is official_brand_for(b_rd, brands)


def analyze_html(html: str, page_url: str, brands: list[Brand]) -> tuple[CheckResult, str | None]:
    """HTML 문자열만으로 판정 (네트워크 없음). (결과, 파비콘 URL) 반환."""
    r = CheckResult(KEY, TITLE)
    soup = BeautifulSoup(html, "html.parser")
    page = parse_url(page_url)
    page_rd = page.registered_domain
    page_brand = official_brand_for(page_rd, brands)

    forms_info = []
    password_forms = 0
    for form in soup.find_all("form"):
        action_raw = (form.get("action") or "").strip()
        action = urljoin(page_url, action_raw) if action_raw else page_url
        has_pw = form.find("input", attrs={"type": lambda t: t and t.lower() == "password"}) is not None
        password_forms += has_pw
        info = {"action": action, "method": (form.get("method") or "get").lower(), "has_password": has_pw}
        forms_info.append(info)

        if action.lower().startswith("mailto:"):
            r.add(f"폼이 이메일(mailto:)로 전송됨 → {action[:80]}", 0.5)
            continue
        if not action.lower().startswith(("http://", "https://")):
            continue
        action_rd = registered_domain_of(action)
        info["action_domain"] = action_rd
        if not _same_owner(action_rd, page_rd, brands):
            if has_pw:
                r.add(f"비밀번호 폼이 외부 도메인({action_rd})으로 전송됨", 0.8)
            else:
                r.add(f"폼이 외부 도메인({action_rd})으로 전송됨", 0.15)
        if has_pw and page.scheme == "https" and action.lower().startswith("http://"):
            r.add("HTTPS 페이지의 비밀번호 폼이 평문 HTTP로 전송됨", 0.3)

    if password_forms:
        r.add(f"로그인(비밀번호 입력) 폼 {password_forms}개 존재", 0.15 if not page_brand else 0.0)

    # 파비콘: <link rel="icon">, 없으면 /favicon.ico
    icon_href = None
    for link in soup.find_all("link", href=True):
        rel = " ".join(link.get("rel") or []).lower()
        if "icon" in rel:
            icon_href = urljoin(page_url, link["href"])
            break
    favicon_url = icon_href or urljoin(page_url, "/favicon.ico")
    if icon_href and icon_href.lower().startswith(("http://", "https://")):
        icon_rd = registered_domain_of(icon_href)
        icon_brand = official_brand_for(icon_rd, brands)
        if icon_brand and icon_brand is not page_brand:
            r.add(f"파비콘을 '{icon_brand.name}' 공식 도메인({icon_rd})에서 직접 가져옴 - 페이지 도메인은 {page_rd}", 0.7)

    title = (soup.title.string or "").strip() if soup.title and soup.title.string else ""
    if title and not page_brand:
        tl = title.lower()
        hit = next((b for b in brands if len(b.name) >= 4 and b.name in tl), None)
        if hit:
            r.add(f"페이지 제목에 브랜드명 '{hit.name}' 포함 (\"{title[:60]}\") - 도메인은 공식 아님", 0.2)

    r.data = {"final_url": page_url, "title": title[:200], "forms": forms_info[:20],
              "password_forms": password_forms, "favicon_url": favicon_url}
    return r, favicon_url


async def check_content(p, final_url: str, brands: list[Brand], timeout: float,
                        client: httpx.AsyncClient) -> CheckResult:
    try:
        resp = await _get_limited(client, final_url, MAX_HTML_BYTES, timeout)
    except httpx.TimeoutException:
        return CheckResult.unavailable(KEY, TITLE, f"HTML 요청 타임아웃({timeout:g}초)")
    except httpx.HTTPError as e:
        return CheckResult.unavailable(KEY, TITLE, f"HTML 요청 실패 ({e.__class__.__name__})")

    ctype = resp.content_type
    if "html" not in ctype.lower():
        return CheckResult.skipped(KEY, TITLE, f"HTML 아님 (Content-Type: {ctype or '없음'}, HTTP {resp.status_code})")

    page_url = resp.url
    r, favicon_url = analyze_html(resp.text, page_url, brands)
    r.data["http_status"] = resp.status_code

    # 파비콘 해시 비교 (brands.json 에 favicon_sha256 이 등록된 브랜드만)
    if favicon_url and any(b.favicon_sha256 for b in brands):
        try:
            fav = await _get_limited(client, favicon_url, MAX_FAVICON_BYTES, timeout)
            if fav.status_code == 200 and fav.body:
                digest = favicon_sha256(fav.body)
                r.data["favicon_sha256"] = digest
                page_brand = official_brand_for(registered_domain_of(page_url), brands)
                for b in brands:
                    if digest in b.favicon_sha256 and b is not page_brand:
                        r.add(f"파비콘이 '{b.name}' 공식 파비콘과 동일(SHA-256 일치) - 도메인은 {registered_domain_of(page_url)}", 0.8)
                        break
        except httpx.HTTPError:
            r.data["favicon_error"] = "파비콘 다운로드 실패"
    return r.finalize()
