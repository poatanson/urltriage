"""SSL/TLS 인증서 체크.

두 개의 결과를 낸다(가중치를 따로 주기 위해):
- ssl        : 인증서 존재/신뢰 체인/만료/도메인 일치 여부 (가중치 중간)
- ssl_issuer : 발급기관이 무료 자동발급 CA인지 (단독으로는 위험 신호가 아니므로 가중치 낮음)
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime

from urltriage.models import CheckResult
from urltriage.urlutils import ParsedURL

KEY = "ssl"
TITLE = "SSL 인증서"
ISSUER_KEY = "ssl_issuer"
ISSUER_TITLE = "인증서 발급기관"

# 누구나 즉시 무료로 발급받을 수 있는 ACME 기반 CA (피싱 사이트에서 흔하지만 정상 사이트도 매우 많이 사용)
FREE_CAS = ("let's encrypt", "zerossl", "buypass", "cpanel")

# OpenSSL X509_V_ERR_* 코드 → (설명, 위험도)
VERIFY_ERRORS = {
    62: ("인증서 도메인 불일치 (다른 사이트의 인증서)", 0.9),
    18: ("자체 서명 인증서", 0.8),
    19: ("자체 서명 루트를 포함한 체인", 0.8),
    10: ("인증서 만료", 0.7),
    9: ("인증서 유효기간 시작 전", 0.6),
    20: ("신뢰할 수 없는 발급기관 (로컬 issuer 확인 불가)", 0.7),
    21: ("체인 검증 불가 (중간 인증서 누락)", 0.4),
    23: ("인증서 폐기됨", 0.9),
}


def _name_field(name_seq, field: str) -> str | None:
    for rdn in name_seq or ():
        for k, v in rdn:
            if k == field:
                return v
    return None


def hostname_matches(host: str, patterns: list[str]) -> bool:
    """RFC 6125 단순 구현: 와일드카드는 가장 왼쪽 레이블 하나만 대체."""
    host = host.lower().rstrip(".")
    for pat in patterns:
        pat = pat.lower().rstrip(".")
        if pat == host:
            return True
        if pat.startswith("*."):
            suffix = pat[1:]  # ".example.com"
            if host.endswith(suffix) and "." not in host[: -len(suffix)] and host[: -len(suffix)]:
                return True
    return False


def _parse_cert_time(s: str) -> datetime:
    return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)


async def _handshake(host: str, port: int, timeout: float) -> dict:
    ctx = ssl.create_default_context()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout
    )
    try:
        return writer.get_extra_info("peercert") or {}
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1)
        except Exception:  # noqa: BLE001
            pass


async def check_ssl(p: ParsedURL, timeout: float = 5.0) -> tuple[CheckResult, CheckResult]:
    host = p.host
    port = p.port if (p.scheme == "https" and p.port) else 443
    r = CheckResult(KEY, TITLE, data={"host": host, "port": port})

    try:
        cert = await _handshake(host, port, timeout)
    except ssl.SSLCertVerificationError as e:
        desc, risk = VERIFY_ERRORS.get(e.verify_code, (f"인증서 검증 실패 ({e.verify_message})", 0.6))
        r.add(f"{desc} - {e.verify_message}", risk)
        r.data.update(verify_code=e.verify_code, verify_message=e.verify_message)
        return r.finalize(), CheckResult.unavailable(ISSUER_KEY, ISSUER_TITLE, "인증서 검증 실패로 발급기관 판정 생략")
    except ConnectionRefusedError:
        r.add(f"HTTPS({port}) 연결 거부 - 암호화 통신 미제공", 0.6)
        return r.finalize(), CheckResult.skipped(ISSUER_KEY, ISSUER_TITLE, "인증서 없음")
    except ssl.SSLError as e:
        r.add(f"TLS 핸드셰이크 실패 ({e.reason or e})", 0.5)
        return r.finalize(), CheckResult.skipped(ISSUER_KEY, ISSUER_TITLE, "인증서 없음")
    except TimeoutError:
        reason = f"TLS 연결 타임아웃({timeout:g}초)"
        return (CheckResult.unavailable(KEY, TITLE, reason),
                CheckResult.unavailable(ISSUER_KEY, ISSUER_TITLE, reason))
    except (socket.gaierror, OSError) as e:
        reason = f"연결 실패 ({e.__class__.__name__}: {e})"
        return (CheckResult.unavailable(KEY, TITLE, reason),
                CheckResult.unavailable(ISSUER_KEY, ISSUER_TITLE, reason))

    subject_cn = _name_field(cert.get("subject"), "commonName")
    issuer_o = _name_field(cert.get("issuer"), "organizationName") or ""
    issuer_cn = _name_field(cert.get("issuer"), "commonName") or ""
    sans = [v for k, v in cert.get("subjectAltName", ()) if k in ("DNS", "IP Address")]
    not_before = _parse_cert_time(cert["notBefore"]) if "notBefore" in cert else None
    not_after = _parse_cert_time(cert["notAfter"]) if "notAfter" in cert else None
    now = datetime.now(UTC)
    matched = hostname_matches(host, sans or ([subject_cn] if subject_cn else []))

    r.data.update(
        subject_cn=subject_cn, issuer_org=issuer_o, issuer_cn=issuer_cn, san_count=len(sans),
        san_sample=sans[:5], hostname_match=matched,
        not_before=not_before.isoformat() if not_before else None,
        not_after=not_after.isoformat() if not_after else None,
        days_remaining=(not_after - now).days if not_after else None,
    )
    # 핸드셰이크 검증(check_hostname=True)을 통과했으므로 일치해야 정상. 직접 재확인한 결과도 기록.
    if not matched:
        r.add("인증서 SAN/CN에 접속 호스트가 없음", 0.9)
    r.data["note"] = f"유효한 인증서 (발급: {issuer_o or issuer_cn}, 만료까지 {r.data['days_remaining']}일)"

    ir = CheckResult(ISSUER_KEY, ISSUER_TITLE, data={"issuer_org": issuer_o, "issuer_cn": issuer_cn})
    issuer_text = f"{issuer_o} {issuer_cn}".lower()
    free = next((ca for ca in FREE_CAS if ca in issuer_text), None)
    if free:
        ir.add(f"무료 자동발급 CA ({issuer_o or issuer_cn}) - 단독으로는 위험 신호 아님", 0.6)
    if not_before and (now - not_before).days < 7:
        ir.add(f"인증서가 {max(0, (now - not_before).days)}일 전에 발급됨", 0.4)
    ir.data["free_ca"] = bool(free)
    return r.finalize(), ir.finalize()
