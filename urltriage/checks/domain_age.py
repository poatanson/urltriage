"""도메인 나이 체크: python-whois로 생성일 조회, 실패 시 RDAP(HTTP/JSON)로 대체 조회.

whois는 블로킹 소켓 I/O이므로 스레드에서 실행하고 asyncio 타임아웃을 건다.
둘 다 실패하면 '확인불가'(UNAVAILABLE) → 점수 계산에서 제외.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

import httpx

from urltriage.models import CheckResult
from urltriage.net import USER_AGENT
from urltriage.urlutils import ParsedURL

KEY = "domain_age"
TITLE = "도메인 나이"

RDAP_URL = "https://rdap.org/domain/{domain}"

# python-whois는 실패 시 logger.error로 스택을 찍으므로 조용히
logging.getLogger("whois").setLevel(logging.CRITICAL)
logging.getLogger("whois.whois").setLevel(logging.CRITICAL)

# (최대 일수, 위험도, 설명) — 위에서부터 첫 조건에 걸리면 적용
AGE_BANDS = (
    (30, 1.0, "30일 미만 신규 도메인 (피싱 도메인 대부분이 등록 직후 사용됨)"),
    (90, 0.6, "90일 미만 도메인"),
    (180, 0.4, "180일 미만 도메인"),
    (365, 0.2, "1년 미만 도메인"),
)


def _to_datetime(value: Any) -> datetime | None:
    if isinstance(value, list):
        dates = [d for d in (_to_datetime(v) for v in value) if d]
        return min(dates) if dates else None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(value, fmt)
                return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
            except ValueError:
                continue
    return None


def _whois_lookup(domain: str, timeout: float) -> dict[str, Any]:
    import whois  # 지연 import: 설치 안 된 환경에서도 RDAP 경로는 동작하도록

    w = whois.whois(domain, quiet=True, timeout=int(max(1, timeout)))
    return {"creation_date": w.get("creation_date"), "registrar": w.get("registrar")}


async def _via_whois(domain: str, timeout: float) -> tuple[datetime | None, str, str | None]:
    """(생성일, 출처, registrar). 실패 시 예외."""
    info = await asyncio.wait_for(asyncio.to_thread(_whois_lookup, domain, timeout), timeout)
    return _to_datetime(info["creation_date"]), "whois", info.get("registrar")


async def _via_rdap(domain: str, timeout: float) -> tuple[datetime | None, str, str | None]:
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                 headers={"User-Agent": USER_AGENT}) as client:
        resp = await client.get(RDAP_URL.format(domain=domain))
    if resp.status_code == 404:
        raise LookupError("RDAP: 등록 정보 없음 (미등록 도메인이거나 RDAP 미지원 TLD)")
    resp.raise_for_status()
    data = resp.json()
    created = None
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration":
            created = _to_datetime(ev.get("eventDate"))
    registrar = None
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            vcard = ent.get("vcardArray", [None, []])[1]
            registrar = next((v[3] for v in vcard if v and v[0] == "fn"), None)
    return created, "rdap", registrar


async def check_domain_age(p: ParsedURL, timeout: float = 5.0, now: datetime | None = None,
                           use_rdap_fallback: bool = True) -> CheckResult:
    if p.is_ip:
        return CheckResult.skipped(KEY, TITLE, "IP 주소 호스트 - whois 대상 아님")
    domain = p.registered_domain
    errors: list[str] = []
    created = source = registrar = None

    lookups = [_via_whois] + ([_via_rdap] if use_rdap_fallback else [])
    for lookup in lookups:
        try:
            created, source, registrar = await lookup(domain, timeout)
            if created:
                break
            errors.append(f"{lookup.__name__[5:]}: 생성일 필드 없음")
        except TimeoutError:
            errors.append(f"{lookup.__name__[5:]}: 타임아웃({timeout:g}초)")
        except Exception as e:  # noqa: BLE001 - 라이브러리마다 예외 타입이 제각각
            msg = str(e).strip().splitlines()[0][:120] if str(e).strip() else e.__class__.__name__
            errors.append(f"{lookup.__name__[5:]}: {msg}")

    if not created:
        return CheckResult.unavailable(KEY, TITLE, "; ".join(errors) or "생성일 조회 실패", domain=domain)

    now = now or datetime.now(UTC)
    age_days = (now - created).days
    r = CheckResult(KEY, TITLE, data={
        "domain": domain, "created": created.isoformat(), "age_days": age_days,
        "source": source, "registrar": registrar,
    })
    for max_days, risk, desc in AGE_BANDS:
        if age_days < max_days:
            r.add(f"{desc}: {age_days}일 (생성 {created:%Y-%m-%d}, 출처 {source})", risk)
            break
    else:
        r.data["note"] = f"생성 {created:%Y-%m-%d} ({age_days // 365}년 이상), 출처 {source}"
    return r.finalize()
