from core.finding import Finding, Severity
from core.gate import evaluate

LIMITS = {"critical": 1, "high": 5}


def make(severity, category="dependency"):
    return Finding(
        tool="t",
        rule="r",
        category=category,
        severity=severity,
        location="x",
    )


def test_no_findings_passes():
    assert evaluate([], LIMITS).passed is True


def test_one_critical_fails():
    result = evaluate([make(Severity.CRITICAL)], LIMITS)
    assert result.passed is False
    assert "critical" in result.reasons[0]


def test_four_highs_pass_five_fail():
    assert evaluate([make(Severity.HIGH)] * 4, LIMITS).passed is True
    assert evaluate([make(Severity.HIGH)] * 5, LIMITS).passed is False


def test_medium_and_low_never_fail():
    findings = [make(Severity.MEDIUM)] * 50 + [make(Severity.LOW)] * 50
    assert evaluate(findings, LIMITS).passed is True


def test_secret_fails_even_if_severity_is_low():
    result = evaluate([make(Severity.LOW, category="secret")], LIMITS)
    assert result.passed is False
    assert "secret detected" in result.reasons


def test_secret_rule_can_be_turned_off():
    findings = [make(Severity.LOW, category="secret")]
    assert evaluate(findings, LIMITS, fail_on_secret=False).passed is True