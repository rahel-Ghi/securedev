from pydantic import BaseModel

from core.config import Config
from core.finding import Finding
from core.gate import GateResult, evaluate
from core.registry import discover


class ScanFailure(BaseModel):
    scanner: str
    error: str


class RunResult(BaseModel):
    findings: list[Finding]
    failures: list[ScanFailure]
    gate: GateResult


def run_scan(target: str, config: Config, available=None) -> RunResult:
    available = available if available is not None else discover()
    findings: list[Finding] = []
    failures: list[ScanFailure] = []

    for name in config.enabled_scanners():
        cls = available.get(name)
        if cls is None:
            failures.append(ScanFailure(scanner=name, error="no such plug-in"))
            continue
        try:
            scanner = cls()
            findings.extend(scanner.parse(scanner.run(target)))
        except Exception as exc:  # one failing scanner must not stop the run
            failures.append(ScanFailure(scanner=name, error=str(exc)))

    gate = evaluate(findings, config.gate.fail_on, config.gate.fail_on_secret)
    return RunResult(findings=findings, failures=failures, gate=gate)