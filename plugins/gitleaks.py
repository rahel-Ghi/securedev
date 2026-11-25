import hashlib
import json

from core.finding import Finding, Severity
from core.plugin import Scanner


class GitleaksScanner(Scanner):
    name = "gitleaks"

    def run(self, target: str) -> str:
        raise NotImplementedError("run() comes next, using Docker")

    def parse(self, raw: str) -> list[Finding]:
        if not raw.strip():
            return []
        findings = []
        for item in json.loads(raw):
            location = f"{item['File']}:{item['StartLine']}"
            key = f"secret|{location}|{item['RuleID']}"
            findings.append(
                Finding(
                    tool=self.name,
                    rule=item["RuleID"],
                    category="secret",
                    severity=Severity.HIGH,
                    location=location,
                    fingerprint=hashlib.sha256(key.encode()).hexdigest()[:16],
                )
            )
        return findings