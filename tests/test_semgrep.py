from pathlib import Path

from core.finding import Severity
from plugins.semgrep import SemgrepScanner

SAMPLE = Path(__file__).parent / "data" / "semgrep_sample.json"


def test_parse_real_report():
    findings = SemgrepScanner().parse(SAMPLE.read_text(encoding="utf-8"))
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "semgrep"
    assert f.category == "code"
    assert f.severity == Severity.HIGH
    assert f.location == "app.py:13"
    assert "subprocess-shell-true" in f.rule


def test_parse_empty_and_clean_reports():
    assert SemgrepScanner().parse("") == []
    assert SemgrepScanner().parse("{}") == []
    assert SemgrepScanner().parse('{"results": []}') == []


def test_warning_and_info_mapping():
    raw = (
        '{"results":['
        '{"check_id":"a","path":"/src/x.py","start":{"line":1},'
        '"extra":{"severity":"WARNING"}},'
        '{"check_id":"b","path":"/src/y.py","start":{"line":2},'
        '"extra":{"severity":"INFO"}}]}'
    )
    sev = [f.severity for f in SemgrepScanner().parse(raw)]
    assert sev == [Severity.MEDIUM, Severity.LOW]


def test_fingerprint_is_stable():
    a = SemgrepScanner().parse(SAMPLE.read_text(encoding="utf-8"))[0]
    b = SemgrepScanner().parse(SAMPLE.read_text(encoding="utf-8"))[0]
    assert a.fingerprint == b.fingerprint != ""