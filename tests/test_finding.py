from core.finding import Finding, Severity


def test_finding_has_required_fields():
    f = Finding(
        tool="gitleaks",
        rule="generic-api-key",
        category="secret",
        severity=Severity.HIGH,
        location="app/config.py:12",
    )
    assert f.tool == "gitleaks"
    assert f.severity == Severity.HIGH
    assert f.cve is None
    assert f.fingerprint == ""


def test_severity_accepts_text_value():
    f = Finding(
        tool="trivy",
        rule="CVE-2023-0001",
        category="dependency",
        severity="critical",
        location="requests==2.0.0",
        cve="CVE-2023-0001",
    )
    assert f.severity is Severity.CRITICAL