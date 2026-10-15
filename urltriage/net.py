"""네트워크 공통 유틸 (DNS 해석, HTTP 클라이언트 설정)."""

from __future__ import annotations

import asyncio
import socket

import httpx

USER_AGENT = "urltriage/0.1 (+phishing-detection; defensive scanner)"


class DNSError(Exception):
    pass


async def resolve(host: str, timeout: float) -> list[str]:
    """호스트를 IP 목록으로 해석. 실패/타임아웃 시 DNSError."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout
        )
    except (socket.gaierror, UnicodeError) as e:
        raise DNSError(f"DNS 해석 실패 ({e.__class__.__name__}: {e})") from e
    except TimeoutError as e:
        raise DNSError(f"DNS 해석 타임아웃 ({timeout:g}초)") from e
    return sorted({info[4][0] for info in infos})


def http_client(timeout: float) -> httpx.AsyncClient:
    """리다이렉트는 직접 따라가며 기록하므로 follow_redirects=False.
    verify=False: 인증서 문제는 SSL 체크가 따로 판정하고, 여기선 체인 추적이 목적."""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
        verify=False,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"},
    )
