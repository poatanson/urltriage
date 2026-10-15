"""리다이렉트 체인 추적.

httpx로 리다이렉트를 직접 한 단계씩 따라가며 기록한다(최대 MAX_HOPS).
본문은 읽지 않고 헤더만 사용(stream 모드). 최종 목적지 도메인이 다르면 그 도메인에
대해서도 타이포스쿼팅/구조 검사를 재실행해 근거에 포함한다.
"""

from __future__ import annotations

from urllib.parse import urljoin

import httpx

from urltriage.checks.structure import URL_SHORTENERS
from urltriage.checks.typosquat import Brand, check_typosquat, official_brand_for
from urltriage.models import CheckResult
from urltriage.net import http_client
from urltriage.urlutils import parse_url

KEY = "redirects"
TITLE = "리다이렉트 체인"

MAX_HOPS = 10
REDIRECT_CODES = {301, 302, 303, 307, 308}


async def trace_redirects(url: str, timeout: float, client: httpx.AsyncClient | None = None) -> dict:
    """{'chain': [{'url','status','location'}...], 'final_url', 'error'}"""
    own = client is None
    client = client or http_client(timeout)
    chain: list[dict] = []
    current = url
    error = None
    try:
        for _ in range(MAX_HOPS + 1):
            async with client.stream("GET", current) as resp:
                loc = resp.headers.get("location")
                chain.append({"url": current, "status": resp.status_code, "location": loc})
                if resp.status_code in REDIRECT_CODES and loc:
                    current = urljoin(current, loc)
                    continue
                break
        else:
            error = f"리다이렉트가 {MAX_HOPS}회를 초과 (무한 루프 가능)"
    except httpx.TimeoutException:
        error = f"타임아웃({timeout:g}초)"
    except httpx.HTTPError as e:
        error = f"{e.__class__.__name__}: {e}"[:160]
    finally:
        if own:
            await client.aclose()
    return {"chain": chain, "final_url": chain[-1]["url"] if chain else None, "error": error}


async def check_redirects(p, brands: list[Brand], timeout: float = 5.0,
                          client: httpx.AsyncClient | None = None) -> CheckResult:
    traced = await trace_redirects(p.url, timeout, client)
    chain, err = traced["chain"], traced["error"]
    if not chain:
        return CheckResult.unavailable(KEY, TITLE, err or "응답 없음")

    r = CheckResult(KEY, TITLE, data=traced)
    hops = len(chain) - 1
    r.data["hops"] = hops
    if err and "초과" in err:
        r.add(err, 0.6)
    elif err:
        # 첫 응답은 받았지만 중간 홉에서 실패 → 받은 데까지로 판정
        r.data["partial"] = True

    final = parse_url(chain[-1]["url"])
    orig_rd, final_rd = p.registered_domain, final.registered_domain
    r.data["final_registered_domain"] = final_rd

    if hops > 5:
        r.add(f"리다이렉트 횟수 과다 ({hops}회)", 0.4)
    elif hops >= 3:
        r.add(f"리다이렉트 다수 ({hops}회)", 0.2)

    if final_rd != orig_rd:
        shortener = orig_rd in URL_SHORTENERS
        same_brand = (b1 := official_brand_for(orig_rd, brands)) is not None and b1 is official_brand_for(final_rd, brands)
        if same_brand:
            r.data["note"] = f"동일 브랜드의 공식 도메인으로 이동 ({orig_rd} → {final_rd})"
        else:
            r.add(f"최종 목적지 도메인이 다름: {orig_rd} → {final_rd}"
                  + (" (단축 URL)" if shortener else ""), 0.2 if shortener else 0.4)
            # 최종 도메인이 브랜드 사칭인지 재검사 (단축 URL 뒤에 숨은 피싱 탐지)
            final_typo = check_typosquat(final, brands)
            if final_typo.risk > 0:
                r.add(f"최종 목적지 사칭 의심: {final_typo.findings[0].message}", 0.8 * final_typo.risk)
            r.data["final_typosquat"] = final_typo.to_dict()
    elif hops:
        r.data["note"] = f"같은 도메인 내 이동 {hops}회 ({chain[0]['url']} → {chain[-1]['url']})"

    if final.is_ip and not p.is_ip:
        r.add(f"최종 목적지가 IP 주소 ({final.host})", 0.5)

    schemes = [parse_url(c["url"]).scheme for c in chain]
    if "https" in schemes and schemes[-1] == "http":
        r.add("HTTPS → HTTP 다운그레이드", 0.3)
    return r.finalize()
