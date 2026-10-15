"""명령줄 인터페이스."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn

from urltriage import __version__
from urltriage.analyzer import Options, analyze_many
from urltriage.checks.typosquat import DEFAULT_BRANDS_PATH, load_brands
from urltriage.report import print_reports, write_json

FAIL_LEVELS = {"medium": 25, "high": 50, "critical": 75}

EPILOG = """\
예시:
  urltriage -u https://example.com
  urltriage -u g00gle-login.tk -u paypa1.com --offline
  urltriage -f urls.txt --deep --json reports/result.json
  urltriage -f urls.txt --summary-only --fail-on high   # CI 등에서 High 이상이면 종료코드 2

종료 코드: 0=정상, 2=입력 오류 또는 --fail-on 기준 이상 URL 존재
"""


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="urltriage",
        description="피싱 URL/도메인 위험도 탐지기 (방어/탐지 목적)",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = ap.add_argument_group("입력")
    src.add_argument("-u", "--url", action="append", default=[], metavar="URL",
                     help="검사할 URL (여러 번 지정 가능)")
    src.add_argument("-f", "--file", type=Path, metavar="FILE",
                     help="URL 목록 파일 (한 줄에 하나, '#' 주석/빈 줄 무시)")

    chk = ap.add_argument_group("검사 옵션")
    chk.add_argument("--deep", action="store_true", help="HTML 콘텐츠 분석(로그인 폼, 폼 전송 도메인, 파비콘)까지 수행")
    chk.add_argument("--offline", action="store_true",
                     help="네트워크 접속 없이 URL 구조/타이포스쿼팅만 검사 (whois/SSL/리다이렉트/HTML 생략)")
    chk.add_argument("-t", "--timeout", type=float, default=5.0, metavar="SEC",
                     help="네트워크 호출별 타임아웃(초, 기본 5)")
    chk.add_argument("-c", "--concurrency", type=int, default=10, metavar="N", help="동시 처리 URL 수 (기본 10)")
    chk.add_argument("--brands", type=Path, default=DEFAULT_BRANDS_PATH, metavar="JSON",
                     help="브랜드 목록 JSON 경로 (기본: 내장 data/brands.json)")

    out = ap.add_argument_group("출력")
    out.add_argument("--json", type=Path, metavar="PATH", help="상세 리포트를 JSON 파일로 저장")
    out.add_argument("--summary-only", action="store_true", help="항목별 상세 표 없이 요약 표만 출력")
    out.add_argument("--fail-on", choices=list(FAIL_LEVELS), help="이 등급 이상인 URL이 있으면 종료코드 2")
    out.add_argument("--no-color", action="store_true", help="색상 끄기")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def read_url_file(path: Path) -> list[str]:
    urls = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        # 줄 전체 주석만 무시 (URL 안의 '#fragment'는 보존)
        if line and not line.startswith("#"):
            urls.append(line)
    return urls


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    ap = build_parser()
    args = ap.parse_args(argv)
    console = Console(no_color=args.no_color, highlight=False)

    urls = list(args.url)
    if args.file:
        if not args.file.is_file():
            ap.error(f"파일을 찾을 수 없음: {args.file}")
        urls += read_url_file(args.file)
    urls = list(dict.fromkeys(u.strip() for u in urls if u.strip()))  # 순서 유지 중복 제거
    if not urls:
        ap.error("-u URL 또는 -f FILE 중 하나 이상을 지정하세요")
    if args.timeout <= 0:
        ap.error("--timeout 은 0보다 커야 합니다")

    try:
        brands = load_brands(args.brands)
    except (OSError, ValueError, KeyError) as e:
        ap.error(f"브랜드 목록을 읽을 수 없음 ({args.brands}): {e}")

    opts = Options(timeout=args.timeout, deep=args.deep, offline=args.offline, concurrency=args.concurrency)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(),
                  MofNCompleteColumn(), console=console, transient=True) as progress:
        task = progress.add_task(f"{len(urls)}개 URL 분석 중", total=len(urls))
        reports = asyncio.run(analyze_many(urls, brands, opts, on_done=lambda r: progress.advance(task)))

    print_reports(reports, console, summary_only=args.summary_only)

    if args.json:
        path = write_json(args.json, reports, opts)
        console.print(f"[green]JSON 리포트 저장:[/] {path.resolve()}")

    if args.fail_on:
        threshold = FAIL_LEVELS[args.fail_on]
        if any(r.score and r.score.score >= threshold for r in reports):
            return 2
    return 0
