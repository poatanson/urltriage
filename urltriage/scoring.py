"""가중치 기반 점수 산출.

score = Σ(weight_i × risk_i) / Σ(weight_i, 판정된 항목만) × 100
- '확인불가'/'해당없음' 항목은 분모에서 빠진다(가중치 재정규화).
- 그 다음 '격상 규칙'(강한 신호 조합)이 있으면 최소 점수(floor)를 적용한다.
근거는 README의 '채점 기준' 참고.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from urltriage.models import CheckResult, Status

WEIGHTS: dict[str, int] = {
    "typosquat": 25,   # 브랜드 사칭은 피싱의 핵심 특징, 오탐 낮음
    "domain_age": 25,  # 피싱 도메인은 대부분 등록 후 수일 내 사용·폐기
    "structure": 15,   # 개별 휴리스틱은 약하지만 누적되면 의미 있음
    "content": 12,     # --deep: 외부 전송 로그인 폼, 브랜드 파비콘 도용
    "redirects": 10,   # 단축 URL/클로킹 경유
    "ssl": 10,         # 인증서 오류는 강한 신호지만 '정상 인증서'는 피싱에도 흔함
    "ssl_issuer": 3,   # 무료 CA는 정상 사이트도 대다수 사용 → 매우 낮게
}

GRADES = ((75, "Critical"), (50, "High"), (25, "Medium"), (0, "Low"))


def grade_for(score: float) -> str:
    for threshold, name in GRADES:
        if score >= threshold:
            return name
    return "Low"


@dataclass
class Escalation:
    rule: str
    floor: float

    def to_dict(self) -> dict:
        return {"rule": self.rule, "floor": self.floor}


@dataclass
class ScoreResult:
    score: float
    grade: str
    base_score: float
    contributions: dict[str, float]          # 항목별 기여 점수 (재정규화 후, base_score의 구성)
    effective_weights: dict[str, float]      # 재정규화된 가중치 (합 100)
    coverage: float                          # 판정된 가중치 / 전체 가중치 (0~1)
    excluded: dict[str, str] = field(default_factory=dict)  # 제외 항목 → 사유
    escalations: list[Escalation] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 1),
            "grade": self.grade,
            "base_score": round(self.base_score, 1),
            "contributions": {k: round(v, 2) for k, v in self.contributions.items()},
            "effective_weights": {k: round(v, 2) for k, v in self.effective_weights.items()},
            "coverage": round(self.coverage, 3),
            "excluded": self.excluded,
            "escalations": [e.to_dict() for e in self.escalations],
        }


def _risk(checks: dict[str, CheckResult], key: str) -> float:
    c = checks.get(key)
    return c.risk if c and c.status is Status.OK else 0.0


def escalation_rules(checks: dict[str, CheckResult]) -> list[Escalation]:
    """가중 평균은 '강한 신호 하나'를 희석시키므로, 확실한 조합에는 최소 점수를 보장한다."""
    typo, age, content = _risk(checks, "typosquat"), _risk(checks, "domain_age"), _risk(checks, "content")
    ssl, structure = _risk(checks, "ssl"), _risk(checks, "structure")
    out = []
    if typo >= 0.85 and age >= 0.6:
        out.append(Escalation("브랜드 사칭 + 90일 미만 신규 도메인", 85))
    if typo >= 0.85:
        out.append(Escalation("유명 브랜드와 거의 동일한 도메인 (사칭 의심)", 55))
    if content >= 0.8:
        out.append(Escalation("외부 도메인으로 전송하는 로그인 폼 또는 브랜드 파비콘 도용", 60))
    if typo >= 0.6 and ssl >= 0.8:
        out.append(Escalation("브랜드 유사 도메인 + 인증서 불일치/자체서명", 70))
    if age >= 1.0 and structure >= 0.5:
        out.append(Escalation("30일 미만 신규 도메인 + 의심스러운 URL 구조", 60))
    return out


def compute_score(checks: dict[str, CheckResult], weights: dict[str, int] | None = None) -> ScoreResult:
    weights = weights or WEIGHTS
    # 커버리지 분모: 실행을 시도한 항목(해당없음 제외)의 가중치 합
    total_weight = sum(weights.get(k, 0) for k, c in checks.items() if c.status is not Status.SKIPPED)
    included = {k: c for k, c in checks.items() if c.status is Status.OK and weights.get(k, 0) > 0}
    excluded = {k: (c.reason or c.status.value) for k, c in checks.items() if k not in included}
    # deep 미사용 등으로 아예 실행되지 않은 항목
    for k in weights:
        if k not in checks:
            excluded.setdefault(k, "실행 안 함")

    w_sum = sum(weights[k] for k in included)
    if w_sum == 0:
        return ScoreResult(0.0, "Low", 0.0, {}, {}, 0.0, excluded)

    eff = {k: weights[k] / w_sum * 100 for k in included}
    contrib = {k: eff[k] * c.risk for k, c in included.items()}
    base = sum(contrib.values())

    escalations = [e for e in escalation_rules(checks) if e.floor > base]
    score = max([base] + [e.floor for e in escalations])
    # 적용되지 않은(이미 점수가 더 높은) 규칙은 기록하지 않되, 가장 높은 floor 하나만 의미 있음
    if escalations:
        top = max(escalations, key=lambda e: e.floor)
        escalations = [top]

    return ScoreResult(
        score=round(min(100.0, score), 1),
        grade=grade_for(score),
        base_score=base,
        contributions=contrib,
        effective_weights=eff,
        coverage=w_sum / total_weight if total_weight else 0.0,
        excluded=excluded,
        escalations=escalations,
    )
