from core.finding import Finding


def deduplicate(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Keep the first finding for each fingerprint.

    Returns the unique findings and how many duplicates were removed.
    """
    seen = set()
    unique = []
    for f in findings:
        # a finding without a fingerprint can't be compared, so keep it
        if f.fingerprint and f.fingerprint in seen:
            continue
        seen.add(f.fingerprint)
        unique.append(f)
    return unique, len(findings) - len(unique)