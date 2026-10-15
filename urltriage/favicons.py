"""브랜드 공식 사이트의 파비콘 SHA-256 해시를 수집해 brands.json 에 기록한다.

    python -m urltriage.favicons [--brands PATH] [--timeout 5]

공식 도메인(각 브랜드의 첫 번째 domains 항목)에만 접속한다.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from bs4 import BeautifulSoup
from urllib.parse import urljoin

from urltriage.checks.content import MAX_FAVICON_BYTES, MAX_HTML_BYTES, _get_limited, favicon_sha256
from urltriage.checks.typosquat import DEFAULT_BRANDS_PATH
from urltriage.net import http_client


async def collect(domain: str, timeout: float, client) -> set[str]:
    hashes: set[str] = set()
    base = f"https://{domain}/"
    candidates = [urljoin(base, "/favicon.ico")]
    try:
        page = await _get_limited(client, base, MAX_HTML_BYTES, timeout)
        soup = BeautifulSoup(page.text, "html.parser")
        for link in soup.find_all("link", href=True):
            if "icon" in " ".join(link.get("rel") or []).lower():
                candidates.append(urljoin(page.url, link["href"]))
    except Exception:  # noqa: BLE001
        pass
    for url in dict.fromkeys(candidates):
        if not url.startswith("http"):
            continue
        try:
            fav = await _get_limited(client, url, MAX_FAVICON_BYTES, timeout)
            if fav.status_code == 200 and fav.body and "html" not in fav.content_type:
                hashes.add(favicon_sha256(fav.body))
        except Exception:  # noqa: BLE001
            continue
    return hashes


def write_brands(path: Path, raw: dict) -> None:
    """브랜드 한 개당 한 줄로 저장 (사람이 편집하기 쉽게)."""
    lines = ["{", f'  "_comment": {json.dumps(raw.get("_comment", ""), ensure_ascii=False)},', '  "brands": [']
    items = [f"    {json.dumps(b, ensure_ascii=False)}" for b in raw["brands"]]
    lines.append(",\n".join(items))
    lines += ["  ]", "}", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


async def main_async(path: Path, timeout: float) -> None:
    raw = json.loads(path.read_text(encoding="utf-8"))
    async with http_client(timeout) as client:
        results = await asyncio.gather(*(collect(b["domains"][0], timeout, client) for b in raw["brands"]))
    for b, hashes in zip(raw["brands"], results):
        merged = sorted(set(b.get("favicon_sha256", [])) | hashes)
        if merged:
            b["favicon_sha256"] = merged
        print(f"{b['name']:10} {b['domains'][0]:16} 해시 {len(hashes)}개 수집")
    write_brands(path, raw)
    print(f"저장: {path}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--brands", type=Path, default=DEFAULT_BRANDS_PATH)
    ap.add_argument("--timeout", type=float, default=5.0)
    args = ap.parse_args()
    asyncio.run(main_async(args.brands, args.timeout))


if __name__ == "__main__":
    main()
