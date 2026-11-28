from core.finding import Finding, Severity

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

CATEGORY_WEIGHT = {
    "secret": 1.5,
    "dependency": 1.2,
    "dynamic": 1.2,
    "image": 1.2,
    "code": 1.0,
    "dockerfile": 0.8,
}


def score(finding: Finding) -> float:
    """risk = severity weight x category weight (unknown category counts as 1.0)"""
    return round(
        SEVERITY_WEIGHT[finding.severity] * CATEGORY_WEIGHT.get(finding.category, 1.0),
        1,
    )


def rank(findings: list[Finding]) -> list[Finding]:
    """Return copies of the findings with their risk set, highest risk first."""
    scored = [f.model_copy(update={"risk": score(f)}) for f in findings]
    return sorted(scored, key=lambda f: f.risk, reverse=True)