"""URL 구조 휴리스틱 (네트워크 불필요).

각 휴리스틱은 발견 시 고정 위험도를 더하고, 합계는 1.0으로 상한을 둔다.
수치 근거는 README '3. URL 구조 분석' 참고.
"""

from __future__ import annotations

import re

from urltriage.models import CheckResult
from urltriage.urlutils import ParsedURL, parse_ip

KEY = "structure"
TITLE = "URL 구조 분석"

# 무료 등록/악용 빈도가 높다고 알려진 TLD (Spamhaus/Interisle 등 보고서에서 상위권)
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "zip", "mov", "click", "country",
    "work", "rest", "fit", "loan", "kim", "men", "support", "icu", "cam", "buzz",
}

URL_SHORTENERS = {
    "bit.ly", "goo.gl", "t.co", "tinyurl.com", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "t.ly", "han.gl", "me2.do", "url.kr",
}

SENSITIVE_WORDS = (
    "login", "signin", "sign-in", "logon", "verify", "verification", "account",
    "secure", "security", "update", "confirm", "banking", "password", "wallet",
    "unlock", "suspend", "billing", "webscr", "authenticate",
)

STANDARD_PORTS = {80, 443}


def check_structure(p: ParsedURL) -> CheckResult:
    r = CheckResult(KEY, TITLE)
    host = p.host

    if p.is_ip:
        ip = parse_ip(host)
        shown = host if str(ip) == host else f"{host} = {ip}, 난독화 표기"
        r.add(f"도메인 대신 IP 주소 사용 ({shown})", 0.6)

    if p.userinfo:
        r.add(f"URL에 '@' 포함 - 브라우저는 '@' 앞부분({p.userinfo!r})을 무시하고 {host}로 접속", 0.5)
    elif "@" in p.path or "@" in p.query:
        r.add("경로/쿼리에 '@' 포함", 0.1)

    if host.startswith("xn--") or ".xn--" in host:
        r.add("퓨니코드(xn--) 도메인 - IDN 동형문자(homograph) 공격 가능성", 0.3)

    sub_depth = len([s for s in p.subdomain.split(".") if s]) if p.subdomain else 0
    if sub_depth >= 4:
        r.add(f"과도한 서브도메인 깊이 ({sub_depth}단계: {p.subdomain})", 0.35)
    elif sub_depth == 3:
        r.add(f"서브도메인이 많음 ({sub_depth}단계: {p.subdomain})", 0.2)

    n = len(p.url)
    if n > 100:
        r.add(f"URL 길이 과다 ({n}자 > 100)", 0.2)
    elif n > 75:
        r.add(f"URL 길이 다소 김 ({n}자 > 75)", 0.1)

    # 퓨니코드 레이블은 유니코드로 디코드한 뒤 센다 ('xn--', 구분자 '-'는 인코딩 산물)
    dom_hyphens = _unicode_label(p.domain).count("-")
    host_hyphens = sum(_unicode_label(lbl).count("-") for lbl in host.split("."))
    if dom_hyphens >= 2:
        r.add(f"등록 도메인 레이블에 하이픈 과다 ({p.domain!r}, {dom_hyphens}개)", 0.25)
    elif dom_hyphens == 1:
        r.add(f"등록 도메인 레이블에 하이픈 포함 ({p.domain!r})", 0.1)
    if host_hyphens >= 4 and dom_hyphens < host_hyphens:
        r.add(f"호스트 전체 하이픈 과다 ({host_hyphens}개)", 0.15)

    if p.port is not None and p.port not in STANDARD_PORTS:
        r.add(f"비표준 포트 사용 (:{p.port})", 0.25)

    if p.suffix and p.suffix.split(".")[-1] in SUSPICIOUS_TLDS:
        r.add(f"악용 빈도 높은 TLD (.{p.suffix})", 0.2)

    if p.registered_domain in URL_SHORTENERS:
        r.add(f"URL 단축 서비스 ({p.registered_domain}) - 실제 목적지 은닉", 0.15)

    if p.scheme == "http" and _has_explicit_scheme(p.original):
        r.add("암호화되지 않은 http:// 명시", 0.1)

    if "//" in p.path:
        r.add("경로 안에 '//' 포함 (내장 리다이렉트 패턴)", 0.1)

    haystack = f"{p.subdomain}.{p.domain}/{p.path}?{p.query}".lower()
    words = sorted({w for w in SENSITIVE_WORDS if w in haystack})
    if words:
        r.add(f"민감 키워드 포함: {', '.join(words)}", min(0.25, 0.1 * len(words)))

    if re.search(r"%[0-9a-fA-F]{2}", host):
        r.add("호스트에 퍼센트 인코딩 포함", 0.2)

    r.data = {
        "url_length": n,
        "subdomain_depth": sub_depth,
        "hyphens_in_domain": dom_hyphens,
        "is_ip": p.is_ip,
        "port": p.port,
        "suffix": p.suffix,
    }
    return r.finalize()


def _unicode_label(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except UnicodeError:
            return label.removeprefix("xn--")
    return label


def _has_explicit_scheme(raw: str) -> bool:
    return raw.lower().startswith("http://")
