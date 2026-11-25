from pathlib import Path

from plugins.gitleaks import GitleaksScanner

SAMPLE = Path(__file__).parent / "data" / "gitleaks_sample.json"


def test_parse_real_report():
    findings = GitleaksScanner().parse(SAMPLE.read_text())
    assert len(findings) == 2
    assert {f.rule for f in findings} == {"aws-access-token", "generic-api-key"}
    assert all(f.category == "secret" for f in findings)
    assert "config.py:2" in {f.location for f in findings}


def test_parse_does_not_store_the_secret():
    findings = GitleaksScanner().parse(SAMPLE.read_text())
    assert "AKIAQ3ZXWV7TN4HJKP2M" not in str(findings)


def test_parse_empty_report():
    assert GitleaksScanner().parse("") == []
    assert GitleaksScanner().parse("[]") == []