from core.config import Config, ScannerConfig
from core.finding import Finding, Severity
from core.orchestrator import run_scan
from core.plugin import Scanner
from core.registry import discover


def fake_scanner(name, findings=None, fail=False):
    class Fake(Scanner):
        def run(self, target):
            if fail:
                raise RuntimeError("boom")
            return "raw"

        def parse(self, raw):
            return findings or []

    Fake.name = name
    return Fake


def cfg(**scanners):
    return Config(scanners={n: ScannerConfig(enabled=e) for n, e in scanners.items()})


def finding(sev, cat="dependency"):
    return Finding(tool="t", rule="r", category=cat, severity=sev, location="x")


def test_only_enabled_scanners_run():
    avail = {"a": fake_scanner("a", [finding(Severity.LOW)]),
             "b": fake_scanner("b", [finding(Severity.LOW)])}
    result = run_scan(".", cfg(a=True, b=False), avail)
    assert len(result.findings) == 1


def test_one_failing_scanner_does_not_stop_the_run():
    avail = {"bad": fake_scanner("bad", fail=True),
             "ok": fake_scanner("ok", [finding(Severity.LOW)])}
    result = run_scan(".", cfg(bad=True, ok=True), avail)
    assert len(result.findings) == 1
    assert result.failures[0].scanner == "bad"


def test_unknown_plugin_is_reported():
    result = run_scan(".", cfg(ghost=True), {})
    assert result.failures[0].error == "no such plug-in"


def test_gate_is_applied_to_findings():
    avail = {"a": fake_scanner("a", [finding(Severity.CRITICAL)])}
    assert run_scan(".", cfg(a=True), avail).gate.passed is False


def test_discover_finds_gitleaks():
    assert "gitleaks" in discover()