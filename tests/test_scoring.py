import pytest

from urltriage.analyzer import apply_context_adjustments
from urltriage.checks.typosquat import load_brands
from urltriage.models import CheckResult, Status
from urltriage.scoring import WEIGHTS, compute_score, grade_for


def ok(key, risk, **data):
    r = CheckResult(key, key, data=data)
    if risk:
        r.add("x", risk)
    return r.finalize()


def unavailable(key):
    return CheckResult.unavailable(key, key, "timeout")


@pytest.mark.parametrize("score,grade", [(0, "Low"), (24.9, "Low"), (25, "Medium"), (50, "High"), (75, "Critical"), (100, "Critical")])
def test_grades(score, grade):
    assert grade_for(score) == grade


def test_all_clean_is_zero():
    checks = {k: ok(k, 0) for k in WEIGHTS}
    s = compute_score(checks)
    assert s.score == 0 and s.grade == "Low" and s.coverage == 1.0


def test_all_max_is_hundred():
    s = compute_score({k: ok(k, 1.0) for k in WEIGHTS})
    assert s.score == 100


def test_renormalization_excludes_unavailable():
    # structure(15)=1.0, typosquat(25)=0 판정, 나머지 확인불가 → 15/40*100 = 37.5
    checks = {"structure": ok("structure", 1.0), "typosquat": ok("typosquat", 0.0),
              "domain_age": unavailable("domain_age"), "ssl": unavailable("ssl")}
    s = compute_score(checks)
    assert s.base_score == pytest.approx(37.5)
    assert set(s.effective_weights) == {"structure", "typosquat"}
    assert sum(s.effective_weights.values()) == pytest.approx(100)
    assert "domain_age" in s.excluded and "content" in s.excluded


def test_contributions_sum_to_base():
    checks = {"structure": ok("structure", 0.5), "typosquat": ok("typosquat", 0.3), "domain_age": ok("domain_age", 0.6)}
    s = compute_score(checks)
    assert sum(s.contributions.values()) == pytest.approx(s.base_score)


def test_escalation_typo_plus_new_domain():
    checks = {k: ok(k, 0) for k in WEIGHTS}
    checks["typosquat"] = ok("typosquat", 0.9)
    checks["domain_age"] = ok("domain_age", 1.0)
    s = compute_score(checks)
    assert s.base_score < 85 and s.score == 85 and s.grade == "Critical"
    assert len(s.escalations) == 1


def test_free_ca_alone_stays_low():
    checks = {k: ok(k, 0) for k in WEIGHTS}
    checks["ssl_issuer"] = ok("ssl_issuer", 1.0)
    assert compute_score(checks).grade == "Low"


def test_defensive_registration_adjustment():
    brands = load_brands()
    typo = ok("typosquat", 0.9, matched_brand="google")
    redir = ok("redirects", 0.4, final_registered_domain="google.com")
    checks = {"typosquat": typo, "redirects": redir}
    apply_context_adjustments(checks, brands)
    assert typo.risk == pytest.approx(0.18) and typo.data["defensive_registration"]


def test_skipped_not_counted_in_coverage():
    checks = {"structure": ok("structure", 0), "ssl": CheckResult.skipped("ssl", "ssl", "offline")}
    assert compute_score(checks).coverage == 1.0
