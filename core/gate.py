from collections import Counter

from pydantic import BaseModel

from core.finding import Finding, Severity


class GateResult(BaseModel):
    passed: bool
    reasons: list[str] = []


def evaluate(
    findings: list[Finding],
    limits: dict[str, int],
    fail_on_secret: bool = True,
) -> GateResult:
    counts = Counter(f.severity.value for f in findings)
    reasons = []

    for level, limit in limits.items():
        if counts.get(level, 0) >= limit:
            reasons.append(f"{counts[level]} {level} finding(s), limit is {limit}")

    if fail_on_secret and any(f.category == "secret" for f in findings):
        reasons.append("secret detected")

    return GateResult(passed=not reasons, reasons=reasons)