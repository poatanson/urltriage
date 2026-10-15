"""URL 하나(또는 여러 개)를 모든 체크에 통과시키고 점수를 매기는 파이프라인."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from urltriage.checks import content, domain_age, redirects, ssl_cert, structure, typosquat
from urltriage.checks.typosquat import Brand, official_brand_for
from urltriage.models import CheckResult, Status
from urltriage.net import DNSError, http_client, resolve
from urltriage.scoring import ScoreResult, compute_score
from urltriage.urlutils import ParsedURL, parse_url


@dataclass
class Options:
    timeout: float = 5.0
    deep: bool = False
    offline: bool = False
    concurrency: int = 10


@dataclass
class UrlReport:
    input: str
    url: str | None = None
    registered_domain: str | None = None
    checks: dict[str, CheckResult] = field(default_factory=dict)
    score: ScoreResult | None = None
    error: str | None = None
    elapsed: float = 0.0
    resolved_ips: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "input": self.input,
            "url": self.url,
            "registered_domain": self.registered_domain,
            "resolved_ips": self.resolved_ips,
            "error": self.error,
            "elapsed_sec": round(self.elapsed, 2),
            **(self.score.to_dict() if self.score else {"score": None, "grade": None}),
            "checks": {k: c.to_dict() for k, c in self.checks.items()},
        }


def apply_context_adjustments(checks: dict[str, CheckResult], brands: list[Brand]) -> None:
    """체크 간 교차 정보로 위험도를 보정한다.

    방어적 등록: 브랜드 유사 도메인이 그 브랜드의 '공식 도메인'으로 리다이렉트되면
    (예: gooogle.com → google.com) 브랜드 소유자가 오타 도메인을 선점한 경우가 대부분이다.
    """
    typo, redir = checks.get("typosquat"), checks.get("redirects")
    if not (typo and redir and typo.status is Status.OK and redir.status is Status.OK and typo.risk > 0):
        return
    matched = typo.data.get("matched_brand")
    final_rd = redir.data.get("final_registered_domain")
    b = official_brand_for(final_rd or "", brands)
    if b and b.name == matched:
        reduced = round(typo.risk * 0.2, 3)
        typo.add(f"최종 목적지가 '{matched}' 공식 도메인({final_rd}) → 브랜드의 방어적 등록으로 보고 위험도 80% 감산",
                 reduced - typo.risk)
        typo.finalize()
        typo.data["defensive_registration"] = True


async def _network_checks(p: ParsedURL, brands: list[Brand], opts: Options,
                          client: httpx.AsyncClient, report: UrlReport) -> list[CheckResult]:
    """DNS 해석이 되는 경우에만 실제 접속(SSL/리다이렉트/HTML)."""
    keys = [(ssl_cert.KEY, ssl_cert.TITLE), (ssl_cert.ISSUER_KEY, ssl_cert.ISSUER_TITLE),
            (redirects.KEY, redirects.TITLE)]
    if opts.deep:
        keys.append((content.KEY, content.TITLE))
    try:
        report.resolved_ips = [p.host] if p.is_ip else await resolve(p.host, opts.timeout)
    except DNSError as e:
        return [CheckResult.unavailable(k, t, str(e)) for k, t in keys]

    (ssl_r, issuer_r), redir_r = await asyncio.gather(
        ssl_cert.check_ssl(p, opts.timeout),
        redirects.check_redirects(p, brands, opts.timeout, client),
    )
    out = [ssl_r, issuer_r, redir_r]
    if opts.deep:
        final_url = redir_r.data.get("final_url") or p.url
        out.append(await content.check_content(p, final_url, brands, opts.timeout, client))
    return out


async def analyze_url(raw: str, brands: list[Brand], opts: Options,
                      client: httpx.AsyncClient | None = None) -> UrlReport:
    t0 = time.perf_counter()
    report = UrlReport(input=raw)
    try:
        p = parse_url(raw)
    except ValueError as e:
        report.error = str(e)
        return report
    report.url, report.registered_domain = p.url, p.registered_domain

    results = [structure.check_structure(p), typosquat.check_typosquat(p, brands)]

    if opts.offline:
        reason = "--offline 모드"
        results += [
            CheckResult.skipped(domain_age.KEY, domain_age.TITLE, reason),
            CheckResult.skipped(ssl_cert.KEY, ssl_cert.TITLE, reason),
            CheckResult.skipped(ssl_cert.ISSUER_KEY, ssl_cert.ISSUER_TITLE, reason),
            CheckResult.skipped(redirects.KEY, redirects.TITLE, reason),
        ]
        if opts.deep:
            results.append(CheckResult.skipped(content.KEY, content.TITLE, reason))
    else:
        own = client is None
        client = client or http_client(opts.timeout)
        try:
            age_r, net = await asyncio.gather(
                domain_age.check_domain_age(p, opts.timeout),
                _network_checks(p, brands, opts, client, report),
            )
        finally:
            if own:
                await client.aclose()
        results += [age_r, *net]

    report.checks = {r.key: r for r in results}
    apply_context_adjustments(report.checks, brands)
    report.score = compute_score(report.checks)
    report.elapsed = time.perf_counter() - t0
    return report


async def analyze_many(urls: list[str], brands: list[Brand], opts: Options,
                       on_done=None) -> list[UrlReport]:
    """여러 URL을 동시에 분석(세마포어로 동시성 제한). 결과는 입력 순서대로 반환."""
    sem = asyncio.Semaphore(max(1, opts.concurrency))
    async with http_client(opts.timeout) as client:
        async def one(u: str) -> UrlReport:
            async with sem:
                try:
                    rep = await analyze_url(u, brands, opts, client)
                except Exception as e:  # noqa: BLE001 - 한 URL 실패가 전체를 멈추지 않도록
                    rep = UrlReport(input=u, error=f"내부 오류: {e.__class__.__name__}: {e}")
            if on_done:
                on_done(rep)
            return rep
        return list(await asyncio.gather(*(one(u) for u in urls)))


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")
