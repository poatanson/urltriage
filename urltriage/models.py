"""모든 체크 모듈이 공유하는 결과 자료형."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    OK = "ok"                    # 정상적으로 판정됨 → 점수 계산에 포함
    UNAVAILABLE = "unavailable"  # 확인불가(타임아웃/네트워크/whois 실패) → 점수 계산에서 제외
    SKIPPED = "skipped"          # 해당 없음/옵션 꺼짐(--deep 미사용, IP 호스트 등) → 제외


@dataclass
class Finding:
    """체크 내부의 개별 근거 한 줄."""

    message: str
    risk: float  # 이 근거가 체크 위험도에 더한 값 (0.0~1.0)

    def to_dict(self) -> dict[str, Any]:
        return {"message": self.message, "risk": round(self.risk, 3)}


@dataclass
class CheckResult:
    key: str                     # scoring.WEIGHTS 의 키
    title: str                   # 사람이 읽는 이름
    status: Status = Status.OK
    risk: float = 0.0            # 0.0(안전) ~ 1.0(매우 위험)
    findings: list[Finding] = field(default_factory=list)
    reason: str = ""             # UNAVAILABLE/SKIPPED 사유
    data: dict[str, Any] = field(default_factory=dict)  # 원시 측정값(JSON 리포트용)

    def add(self, message: str, risk: float) -> None:
        self.findings.append(Finding(message, risk))

    def finalize(self) -> "CheckResult":
        """근거들의 위험도를 합산하고 1.0으로 상한을 둔다."""
        if self.status is Status.OK:
            self.risk = max(0.0, min(1.0, sum(f.risk for f in self.findings)))
        else:
            self.risk = 0.0
        return self

    @classmethod
    def unavailable(cls, key: str, title: str, reason: str, **data: Any) -> "CheckResult":
        return cls(key, title, Status.UNAVAILABLE, reason=reason, data=dict(data))

    @classmethod
    def skipped(cls, key: str, title: str, reason: str) -> "CheckResult":
        return cls(key, title, Status.SKIPPED, reason=reason)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["risk"] = round(self.risk, 3)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d
