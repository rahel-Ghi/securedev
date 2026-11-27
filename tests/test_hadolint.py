from collections import Counter
from pathlib import Path

from core.finding import Severity
from plugins.hadolint import HadolintScanner

SAMPLE = Path(__file__).parent / "data" / "hadolint_sample.json"


def load():
    return HadolintScanner().parse(SAMPLE.read_text(encoding="utf-8-sig"))


def test_parse_real_report():
    findings = load()
    assert len(findings) == 9
    counts = Counter(f.severity for f in findings)
    assert counts[Severity.HIGH] == 1
    assert counts[Severity.MEDIUM] == 6
    assert counts[Severity.LOW] == 2


def test_error_is_the_add_instead_of_copy():
    by_rule = {f.rule: f for f in load()}
    f = by_rule["DL3020"]
    assert f.location == "Dockerfile:3"
    assert f.category == "dockerfile"
    assert f.severity == Severity.HIGH


def test_empty_report():
    assert HadolintScanner().parse("") == []
    assert HadolintScanner().parse("[]") == []


def test_no_dockerfile_means_nothing_to_scan(tmp_path):
    assert HadolintScanner().run(str(tmp_path)) == "[]"