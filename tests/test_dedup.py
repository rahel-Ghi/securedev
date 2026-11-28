from core.config import Config, ScannerConfig
from core.dedup import deduplicate
from core.finding import Finding, Severity
from core.orchestrator import run_scan
from core.plugin import Scanner


def make(fp, rule="r"):
    return Finding(
        tool="t", rule=rule, category="dependency",
        severity=Severity.HIGH, location="a.py:1", fingerprint=fp,
    )


def test_same_fingerprint_is_kept_once():
    unique, removed = deduplicate([make("x"), make("x"), make("x")])
    assert len(unique) == 1
    assert removed == 2


def test_different_fingerprints_are_all_kept():
    unique, removed = deduplicate([make("x"), make("y")])
    assert len(unique) == 2
    assert removed == 0


def test_findings_without_fingerprint_are_never_merged():
    unique, removed = deduplicate([make(""), make("")])
    assert len(unique) == 2
    assert removed == 0


def test_orchestrator_removes_duplicates_before_the_gate():
    class Dup(Scanner):
        name = "dup"

        def run(self, target):
            return ""

        def parse(self, raw):
            return [make("x")] * 5  # five identical highs

    cfg = Config(scanners={"dup": ScannerConfig(enabled=True)})
    result = run_scan(".", cfg, {"dup": Dup})
    assert len(result.findings) == 1
    assert result.duplicates_removed == 4
    assert result.gate.passed is True  # one high, not five