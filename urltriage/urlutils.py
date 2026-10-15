"""URL 정규화와 호스트/도메인 분해 유틸리티."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import tldextract

# suffix_list_urls=() → 네트워크로 Public Suffix List를 받지 않고 내장 스냅샷만 사용(오프라인 동작 보장)
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


@dataclass(frozen=True)
class ParsedURL:
    original: str      # 사용자가 입력한 그대로
    url: str           # 스킴이 보정된 URL
    scheme: str
    host: str          # 소문자, 대괄호 제거된 호스트
    port: int | None   # URL에 명시된 포트(없으면 None)
    path: str
    query: str
    userinfo: str      # '@' 앞부분 (있으면 위험 신호)
    subdomain: str     # 예: "login.secure"
    domain: str        # 등록 도메인의 레이블. 예: "paypal"
    suffix: str        # 예: "com", "co.kr"
    is_ip: bool

    @property
    def registered_domain(self) -> str:
        """예: 'paypal.com'. IP 이거나 suffix가 없으면 host 그대로."""
        if self.is_ip or not self.suffix or not self.domain:
            return self.host
        return f"{self.domain}.{self.suffix}"

    @property
    def effective_port(self) -> int:
        if self.port is not None:
            return self.port
        return 443 if self.scheme == "https" else 80


def parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """일반 표기뿐 아니라 10진수(3232235777)/16진수(0xC0A80001) 등 난독화 IPv4 표기도 인식."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    h = host.lower()
    try:
        if h.isdigit():
            return ipaddress.IPv4Address(int(h))
        if re.fullmatch(r"0x[0-9a-f]+", h):
            return ipaddress.IPv4Address(int(h, 16))
        # 점으로 구분된 옥텟 중 일부가 16진/8진수인 경우 (예: 0xC0.0xA8.0.1)
        parts = h.split(".")
        if len(parts) == 4 and all(re.fullmatch(r"(0x[0-9a-f]+|0[0-7]*|\d+)", p) for p in parts):
            octets = [int(p, 16) if p.startswith("0x") else int(p, 8) if len(p) > 1 and p.startswith("0") else int(p) for p in parts]
            if all(0 <= o <= 255 for o in octets):
                return ipaddress.IPv4Address(".".join(map(str, octets)))
    except (ValueError, ipaddress.AddressValueError):
        return None
    return None


def parse_url(raw: str) -> ParsedURL:
    raw = raw.strip()
    if not raw:
        raise ValueError("빈 URL")
    url = raw if _SCHEME_RE.match(raw) else f"http://{raw}"
    parts = urlsplit(url)
    netloc = parts.netloc
    userinfo = ""
    if "@" in netloc:
        userinfo, _, netloc = netloc.rpartition("@")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError(f"호스트를 찾을 수 없음: {raw!r}")
    try:
        port = parts.port
    except ValueError:
        raise ValueError(f"잘못된 포트: {raw!r}") from None

    is_ip = parse_ip(host) is not None
    if is_ip:
        sub, dom, suf = "", "", ""
    else:
        ext = _EXTRACT(host)
        sub, dom, suf = ext.subdomain, ext.domain, ext.suffix

    return ParsedURL(
        original=raw,
        url=url,
        scheme=parts.scheme.lower(),
        host=host,
        port=port,
        path=parts.path,
        query=parts.query,
        userinfo=userinfo,
        subdomain=sub,
        domain=dom,
        suffix=suf,
        is_ip=is_ip,
    )


def registered_domain_of(host_or_url: str) -> str:
    """호스트나 URL에서 등록 도메인(eTLD+1)만 뽑는다."""
    try:
        return parse_url(host_or_url).registered_domain
    except ValueError:
        return host_or_url.lower()
