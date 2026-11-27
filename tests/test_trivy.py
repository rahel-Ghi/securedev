from collections import Counter
from pathlib import Path

from core.finding import Severity
from plugins.trivy import TrivyScanner

SAMPLE = Path(__file__).parent / "data" / "trivy_sample.json"


def test_parse_real_report():
    findings = TrivyScanner().parse(SAMPLE.read_text(encoding="utf-8"))
    assert len(findings) == 9
    counts = Counter(f.severity for f in findings)
    assert counts[Severity.HIGH] == 4
    assert counts[Severity.MEDIUM] == 4
    assert counts[Severity.LOW] == 1


def test_parse_fills_cve_and_location():
    findings = TrivyScanner().parse(SAMPLE.read_text(encoding="utf-8"))
    by_id = {f.rule: f for f in findings}
    f = by_id["CVE-2018-1000656"]
    assert f.cve == "CVE-2018-1000656"
    assert f.category == "dependency"
    assert f.location == "requirements.txt:flask@0.12.2"


def test_parse_empty_and_clean_reports():
    assert TrivyScanner().parse("") == []
    assert TrivyScanner().parse("{}") == []
    assert TrivyScanner().parse('{"Results": []}') == []


def test_unknown_severity_becomes_info():
    raw = (
        '{"Results":[{"Target":"t","Vulnerabilities":'
        '[{"VulnerabilityID":"X-1","PkgName":"p",'
        '"InstalledVersion":"1","Severity":"UNKNOWN"}]}]}'
    )
    assert TrivyScanner().parse(raw)[0].severity == Severity.INFO