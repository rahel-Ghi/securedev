from core.finding import Finding, Severity
from core.risk import rank, score


def make(sev, cat):
    return Finding(
        tool="t", rule="r", category=cat, severity=sev, location="x", fingerprint="f"
    )


def test_secret_outranks_dockerfile_at_same_severity():
    assert score(make(Severity.HIGH, "secret")) == 10.5
    assert score(make(Severity.HIGH, "dockerfile")) == 5.6


def test_unknown_category_counts_as_one():
    assert score(make(Severity.HIGH, "something-new")) == 7.0


def test_info_has_no_risk():
    assert score(make(Severity.INFO, "secret")) == 0.0


def test_rank_puts_highest_risk_first_and_fills_risk():
    findings = [
        make(Severity.LOW, "code"),
        make(Severity.CRITICAL, "dependency"),
        make(Severity.HIGH, "secret"),
    ]
    ranked = rank(findings)
    assert [f.risk for f in ranked] == [12.0, 10.5, 1.0]