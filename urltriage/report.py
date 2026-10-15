"""콘솔(rich) 출력과 JSON 리포트."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from urltriage import __version__
from urltriage.analyzer import Options, UrlReport, now_iso
from urltriage.models import Status
from urltriage.scoring import GRADES, WEIGHTS

GRADE_STYLE = {"Low": "bold green", "Medium": "bold yellow", "High": "bold dark_orange", "Critical": "bold white on red"}
GRADE_BORDER = {"Low": "green", "Medium": "yellow", "High": "dark_orange", "Critical": "red"}
STATUS_LABEL = {Status.OK: ("판정", "green"), Status.UNAVAILABLE: ("확인불가", "yellow"), Status.SKIPPED: ("해당없음", "dim")}
CHECK_ORDER = ["typosquat", "domain_age", "structure", "redirects", "ssl", "ssl_issuer", "content"]
LOW_COVERAGE = 0.5


def _grade_text(grade: str | None, score: float | None) -> Text:
    if grade is None:
        return Text("오류", style="bold red")
    return Text(f"{score:5.1f} {grade}", style=GRADE_STYLE.get(grade, ""))


def _top_reasons(rep: UrlReport, n: int = 2) -> str:
    s = rep.score
    if not s:
        return rep.error or ""
    parts = []
    if s.escalations:
        parts.append(f"⚠ {s.escalations[0].rule}")
    for key, pts in sorted(s.contributions.items(), key=lambda kv: kv[1], reverse=True)[:n]:
        if pts <= 0:
            break
        c = rep.checks[key]
        msg = max(c.findings, key=lambda f: f.risk).message if c.findings else c.title
        parts.append(f"{c.title} +{pts:.1f}: {msg}")
    return "\n".join(parts) or "특이사항 없음"


def summary_table(reports: list[UrlReport]) -> Table:
    t = Table(title="피싱 위험도 요약", show_lines=True, expand=True)
    t.add_column("#", justify="right", width=3)
    t.add_column("URL", overflow="fold", ratio=3)
    t.add_column("점수/등급", justify="center", no_wrap=True)
    t.add_column("커버리지", justify="right", no_wrap=True)
    t.add_column("주요 근거", overflow="fold", ratio=5)
    for i, rep in enumerate(reports, 1):
        s = rep.score
        cov = Text(f"{s.coverage * 100:.0f}%", style="yellow" if s.coverage < LOW_COVERAGE else "") if s else Text("-")
        t.add_row(str(i), rep.input, _grade_text(s.grade if s else None, s.score if s else None), cov, _top_reasons(rep))
    return t


def detail_panel(rep: UrlReport) -> Panel:
    s = rep.score
    if not s:
        return Panel(Text(rep.error or "알 수 없는 오류", style="red"), title=rep.input, border_style="red")

    t = Table(show_lines=False, expand=True, pad_edge=False)
    t.add_column("항목", no_wrap=True)
    t.add_column("상태", no_wrap=True)
    t.add_column("가중치", justify="right", no_wrap=True)
    t.add_column("위험도", justify="right", no_wrap=True)
    t.add_column("기여점수", justify="right", no_wrap=True)
    t.add_column("근거", overflow="fold", ratio=1)

    keys = [k for k in CHECK_ORDER if k in rep.checks] + [k for k in rep.checks if k not in CHECK_ORDER]
    for k in keys:
        c = rep.checks[k]
        label, style = STATUS_LABEL[c.status]
        w = WEIGHTS.get(k, 0)
        if c.status is Status.OK:
            weight = f"{w} → {s.effective_weights[k]:.1f}"
            risk = f"{c.risk:.2f}"
            pts = s.contributions[k]
            pts_text = Text(f"+{pts:.1f}", style="bold red" if pts >= 15 else "red" if pts > 0 else "dim")
            lines = [f"• {f.message}" + (f" ({f.risk:+.2f})" if f.risk else "") for f in c.findings]
            if not lines:
                lines = [c.data.get("note") or "이상 없음"]
            evidence = Text("\n".join(lines), style="" if c.findings else "dim")
        else:
            weight, risk, pts_text = f"{w} → 제외", "-", Text("-", style="dim")
            evidence = Text(c.reason, style="dim")
        t.add_row(c.title, Text(label, style=style), weight, risk, pts_text, evidence)
    if "content" not in rep.checks:
        t.add_row("HTML 콘텐츠", Text("미실행", style="dim"), f"{WEIGHTS['content']} → 제외", "-", Text("-", style="dim"),
                  Text("--deep 옵션 사용 시 분석", style="dim"))

    footer = Text()
    footer.append(f"가중 합계 {s.base_score:.1f}점")
    if s.escalations:
        e = s.escalations[0]
        footer.append(f"  →  격상 규칙 적용: {e.rule} (최소 {e.floor:g}점)", style="bold red")
    footer.append(f"  |  최종 {s.score:.1f}점 ", style="bold")
    footer.append(s.grade, style=GRADE_STYLE[s.grade])
    footer.append(f"  |  판정 커버리지 {s.coverage * 100:.0f}%")
    if s.coverage < LOW_COVERAGE:
        footer.append("\n※ 확인불가 항목이 많아 판정된 항목만으로 재정규화됨 - 결과 신뢰도 낮음", style="yellow")
    if rep.resolved_ips:
        footer.append(f"\nIP: {', '.join(rep.resolved_ips[:4])}", style="dim")
    footer.append(f"  소요 {rep.elapsed:.1f}s", style="dim")

    return Panel(Group(t, footer), title=f"[bold]{rep.input}[/]", subtitle=_grade_text(s.grade, s.score),
                 border_style=GRADE_BORDER[s.grade])


def print_reports(reports: list[UrlReport], console: Console, summary_only: bool = False) -> None:
    if not summary_only:
        for rep in reports:
            console.print(detail_panel(rep))
    console.print(summary_table(reports))


def build_json(reports: list[UrlReport], opts: Options) -> dict[str, Any]:
    return {
        "tool": "urltriage",
        "version": __version__,
        "generated_at": now_iso(),
        "options": {"timeout": opts.timeout, "deep": opts.deep, "offline": opts.offline,
                    "concurrency": opts.concurrency},
        "scoring": {"weights": WEIGHTS, "grades": {name: threshold for threshold, name in GRADES}},
        "summary": {g: sum(1 for r in reports if r.score and r.score.grade == g) for _, g in GRADES}
                   | {"error": sum(1 for r in reports if r.error and not r.score)},
        "results": [r.to_dict() for r in reports],
    }


def write_json(path: str | Path, reports: list[UrlReport], opts: Options) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(build_json(reports, opts), ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return p
