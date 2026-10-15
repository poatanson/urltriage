"""타이포스쿼팅 / 콤보스쿼팅 / 동형문자 탐지 (네트워크 불필요).

입력 도메인의 레이블을 브랜드 목록(data/brands.json)과 비교한다.
- 레벤슈타인 거리: 삽입/삭제/치환 1회 = 1
- OSA(제한적 Damerau) 거리: 인접 문자 교환(goolge)도 1로 계산
- 동형문자 정규화: 0→o, 1→l/i, rn→m, vv→w, 키릴/그리스 문자 → 라틴 등
"""

from __future__ import annotations

import itertools
import json
import re
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from urltriage.models import CheckResult
from urltriage.urlutils import ParsedURL

KEY = "typosquat"
TITLE = "타이포스쿼팅"

DEFAULT_BRANDS_PATH = Path(__file__).resolve().parent.parent / "data" / "brands.json"


# --------------------------------------------------------------------------- 거리 함수

def levenshtein(a: str, b: str) -> int:
    """표준 레벤슈타인 거리 (O(len(a)*len(b)), 메모리 O(len(b)))."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def osa_distance(a: str, b: str) -> int:
    """Optimal String Alignment 거리: 레벤슈타인 + 인접 문자 교환(transposition)."""
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


# --------------------------------------------------------------------------- 동형문자 정규화

# 한 글자 → 후보 글자들 (애매한 '1'은 l/i 둘 다)
_CHAR_MAP: dict[str, tuple[str, ...]] = {
    "0": ("o",), "1": ("l", "i"), "3": ("e",), "4": ("a",), "5": ("s",),
    "7": ("t",), "8": ("b",), "9": ("g",), "@": ("a",), "$": ("s",), "!": ("i",), "|": ("l",),
    # 키릴 문자
    "а": ("a",), "е": ("e",), "о": ("o",), "р": ("p",), "с": ("c",), "х": ("x",),
    "у": ("y",), "і": ("i",), "ј": ("j",), "ӏ": ("l",), "ԁ": ("d",), "ѕ": ("s",), "к": ("k",),
    "ո": ("n",), "һ": ("h",), "ԛ": ("q",), "ԝ": ("w",),
    # 그리스 문자
    "ο": ("o",), "α": ("a",), "ν": ("v",), "ρ": ("p",), "τ": ("t",), "ι": ("i",), "κ": ("k",),
}
# 여러 글자 → 한 글자 (rn → m 등)
_SEQ_MAP = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("ii", "u"))

_MAX_VARIANTS = 32


def _decode_idna(label: str) -> str:
    if "xn--" in label:
        try:
            return label.encode("ascii").decode("idna")
        except UnicodeError:
            pass
    return label


@lru_cache(maxsize=4096)
def homoglyph_variants(label: str) -> frozenset[str]:
    """레이블을 라틴 소문자로 '정규화'한 후보 문자열 집합."""
    s = _decode_idna(label).lower()
    # 악센트 제거 (é → e)
    s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
    options = [_CHAR_MAP.get(c, (c,)) for c in s]
    variants: set[str] = set()
    for combo in itertools.islice(itertools.product(*options), _MAX_VARIANTS):
        v = "".join(combo)
        variants.add(v)
        for src, dst in _SEQ_MAP:
            if src in v:
                variants.add(v.replace(src, dst))
    return frozenset(variants)


# --------------------------------------------------------------------------- 브랜드 목록

@dataclass(frozen=True)
class Brand:
    name: str
    domains: tuple[str, ...]
    favicon_sha256: tuple[str, ...] = field(default=())


def load_brands(path: str | Path | None = None) -> list[Brand]:
    p = Path(path) if path else DEFAULT_BRANDS_PATH
    raw = json.loads(p.read_text(encoding="utf-8"))
    items = raw["brands"] if isinstance(raw, dict) else raw
    brands = []
    for it in items:
        brands.append(Brand(
            name=it["name"].lower(),
            domains=tuple(d.lower() for d in it.get("domains", [])),
            favicon_sha256=tuple(h.lower() for h in it.get("favicon_sha256", [])),
        ))
    return brands


def official_brand_for(registered_domain: str, brands: list[Brand]) -> Brand | None:
    rd = registered_domain.lower()
    for b in brands:
        if rd in b.domains:
            return b
    return None


# --------------------------------------------------------------------------- 매칭

@dataclass
class Match:
    brand: str
    where: str          # 비교한 문자열 (레이블/토큰)
    kind: str           # 매칭 유형
    levenshtein: int    # 원문 기준 레벤슈타인 거리
    distance: int       # 동형문자/교환까지 고려한 최소 거리
    risk: float
    message: str

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _best_distance(text: str, brand: str) -> tuple[int, int, bool]:
    """(원문 레벤슈타인, 최소 거리, 동형문자 정규화로 정확히 일치했는지)"""
    lev = levenshtein(text, brand)
    best = min(lev, osa_distance(text, brand))
    homoglyph_exact = False
    for v in homoglyph_variants(text):
        if v == brand and text != brand:
            homoglyph_exact = True
            best = 0
            break
        best = min(best, levenshtein(v, brand))
    return lev, best, homoglyph_exact


def _max_typo_distance(brand: str) -> int:
    """브랜드 길이에 따라 허용 거리: 짧은 이름은 오탐이 많으므로 엄격하게."""
    if len(brand) <= 3:
        return 0
    if len(brand) <= 6:
        return 1
    return 2


def _match_label(label: str, brand: Brand) -> Match | None:
    """등록 도메인 레이블 전체를 브랜드와 비교."""
    lev, dist, homo = _best_distance(label, brand.name)
    if label == brand.name:
        return Match(brand.name, label, "brand-on-unofficial-domain", 0, 0, 0.7,
                     f"브랜드명 '{brand.name}'을 공식이 아닌 도메인에서 사용")
    if homo:
        return Match(brand.name, label, "homoglyph", lev, 0, 1.0,
                     f"'{label}' → 동형문자 치환 시 '{brand.name}'과 동일 (레벤슈타인 {lev})")
    limit = _max_typo_distance(brand.name)
    if 0 < dist <= limit:
        risk = 0.9 if dist == 1 else 0.6
        return Match(brand.name, label, "typo", lev, dist, risk,
                     f"'{label}' ↔ '{brand.name}' 편집 거리 {dist} (레벤슈타인 {lev})")
    return None


def _tokens(s: str) -> list[str]:
    """퓨니코드 레이블은 먼저 유니코드로 디코드한 뒤 '-', '.', '_' 기준으로 나눈다."""
    decoded = ".".join(_decode_idna(lbl) for lbl in s.split("."))
    return [t for t in decoded.replace(".", "-").replace("_", "-").split("-") if t]


def _match_tokens(text: str, brand: Brand, where: str) -> Match | None:
    """하이픈/점으로 나뉜 토큰 중 브랜드(또는 그 오타)가 있는지 (콤보스쿼팅)."""
    best: Match | None = None
    for tok in _tokens(text):
        lev, dist, homo = _best_distance(tok, brand.name)
        if tok == brand.name or homo:
            m = Match(brand.name, tok, f"combo-{where}", lev, 0, 0.85 if where == "domain" else 0.7,
                      f"{'도메인' if where == 'domain' else '서브도메인'} 토큰 '{tok}'이(가) 브랜드 '{brand.name}'"
                      + (" (동형문자)" if homo else "") + "와 일치")
        elif len(brand.name) >= 5 and dist == 1:
            m = Match(brand.name, tok, f"combo-typo-{where}", lev, dist, 0.75 if where == "domain" else 0.6,
                      f"{'도메인' if where == 'domain' else '서브도메인'} 토큰 '{tok}' ↔ '{brand.name}' 편집 거리 1")
        else:
            continue
        if best is None or m.risk > best.risk:
            best = m
    # 하이픈 없이 붙여 쓴 경우 (paypalsecure). 짧은 이름은 일반 단어 오탐(pineapple)이 커서 6자 이상만
    if best is None and where == "domain" and len(brand.name) >= 6 and brand.name in text and text != brand.name:
        best = Match(brand.name, text, "embedded", levenshtein(text, brand.name), 0, 0.6,
                     f"도메인 '{text}' 안에 브랜드명 '{brand.name}' 포함")
    return best


def _contains_domain(text: str, domain: str) -> bool:
    """점 경계 기준으로 text 안에 domain이 통째로 들어있는지 (mypaypal.com 은 paypal.com 아님)."""
    return re.search(rf"(^|[.@/:]){re.escape(domain)}($|[.@/:])", text) is not None


def _match_outside_host(p: ParsedURL, b: Brand) -> list[Match]:
    """호스트 밖(userinfo, 경로)에 브랜드를 넣어 사용자를 속이는 경우."""
    out = []
    if p.userinfo:
        ui = p.userinfo.lower()
        if any(_contains_domain(ui, d) for d in b.domains) or any(
                t == b.name or b.name in homoglyph_variants(t) for t in _tokens(ui.replace(":", "-"))):
            out.append(Match(b.name, p.userinfo, "brand-in-userinfo", 0, 0, 0.85,
                             f"'@' 앞에 '{b.name}' 위장 → 실제 접속지는 {p.host}"))
    if len(b.name) >= 4:
        path_tokens = {t for t in re.split(r"[/._\-]+", p.path.lower()) if t}
        if b.name in path_tokens:
            out.append(Match(b.name, p.path, "brand-in-path", 0, 0, 0.3,
                             f"경로에 브랜드명 '{b.name}' 포함 (호스트 {p.host}는 공식 도메인 아님)"))
    return out


def check_typosquat(p: ParsedURL, brands: list[Brand]) -> CheckResult:
    r = CheckResult(KEY, TITLE)
    if p.is_ip:
        # 도메인 레이블 비교는 불가하지만 userinfo/경로의 브랜드 위장은 판정 가능
        matches = [m for b in brands for m in _match_outside_host(p, b)]
        r.data = {"label": None, "note": "IP 주소 호스트 - 도메인 유사도 비교 생략"}
        return _record(r, matches)

    official = official_brand_for(p.registered_domain, brands)
    # 리포트용: 레이블 전체와 각 토큰 중 브랜드에 가장 가까운 조합
    candidates = {p.domain, *_tokens(p.domain)}
    text, closest = min(((t, b) for t in candidates for b in brands),
                        key=lambda tb: _best_distance(tb[0], tb[1].name)[1])
    lev, dist, _ = _best_distance(text, closest.name)
    r.data = {
        "label": p.domain,
        "closest_text": text,
        "closest_brand": closest.name,
        "levenshtein": lev,
        "min_distance": dist,
        "official_brand": official.name if official else None,
    }
    if official:
        r.data["note"] = f"{official.name} 공식 도메인"
        return r.finalize()

    matches: list[Match] = []
    for b in brands:
        m = _match_label(p.domain, b)
        # 레이블이 토큰 하나뿐이면 토큰 비교는 레이블 비교와 중복이므로 생략
        if m is None and len(_tokens(p.domain)) > 1:
            m = _match_tokens(p.domain, b, "domain")
        elif m is None and len(b.name) >= 6:
            m = _match_tokens(p.domain, b, "domain")  # 붙여 쓴 경우(paypalsecure)만 해당
        if m:
            matches.append(m)
        if p.subdomain:
            m = _match_tokens(p.subdomain, b, "subdomain")
            if m:
                matches.append(m)
            # paypal.com.evil.tk 처럼 공식 도메인 전체를 서브도메인에 넣은 경우
            for d in b.domains:
                if _contains_domain(p.subdomain, d):
                    matches.append(Match(b.name, p.subdomain, "official-domain-in-subdomain", 0, 0, 0.85,
                                         f"서브도메인에 공식 도메인 '{d}' 삽입 → 실제 도메인은 {p.registered_domain}"))
                    break
        matches += _match_outside_host(p, b)
    return _record(r, matches)


def _record(r: CheckResult, matches: list[Match]) -> CheckResult:
    if matches:
        matches.sort(key=lambda m: m.risk, reverse=True)
        top = matches[0]
        r.add(top.message, top.risk)
        # 다른 브랜드/다른 유형의 추가 매칭은 근거로만 기록 (점수는 최상위 1개만 반영)
        seen = {(top.brand, top.kind)}
        for m in matches[1:]:
            if (m.brand, m.kind) not in seen and len(r.findings) < 4:
                r.add(m.message, 0.0)
                seen.add((m.brand, m.kind))
        r.data["matched_brand"] = top.brand
        r.data["matches"] = [m.to_dict() for m in matches]
    return r.finalize()
