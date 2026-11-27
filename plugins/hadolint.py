import hashlib
import json
import subprocess
from pathlib import Path

from core.finding import Finding, Severity
from core.plugin import Scanner
from plugins.gitleaks import ScannerError

IMAGE = "hadolint/hadolint:v2.15.1"

SEVERITY_MAP = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.LOW,
    "style": Severity.INFO,
}


class HadolintScanner(Scanner):
    name = "hadolint"

    def run(self, target: str, timeout: int = 120) -> str:
        if not (Path(target) / "Dockerfile").exists():
            return "[]"  # nothing to check
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{Path(target).resolve()}:/work",
            IMAGE, "hadolint", "--format", "json", "/work/Dockerfile",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                encoding="utf-8", timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise ScannerError(f"hadolint timed out after {timeout}s")
        except FileNotFoundError:
            raise ScannerError("docker command not found")

        # Exit code 0 = clean, 1 = problems found, anything else = failure
        if result.returncode not in (0, 1):
            raise ScannerError(
                f"hadolint failed (exit {result.returncode}): "
                f"{result.stderr.strip()[-300:]}"
            )
        return result.stdout or "[]"

    def parse(self, raw: str) -> list[Finding]:
        if not raw.strip():
            return []
        findings = []
        for item in json.loads(raw):
            path = item["file"]
            if path.startswith("/work/"):
                path = path[len("/work/"):]
            location = f"{path}:{item['line']}"
            rule = item["code"]
            key = f"dockerfile|{location}|{rule}"
            findings.append(
                Finding(
                    tool=self.name,
                    rule=rule,
                    category="dockerfile",
                    severity=SEVERITY_MAP.get(item.get("level"), Severity.LOW),
                    location=location,
                    fingerprint=hashlib.sha256(key.encode()).hexdigest()[:16],
                )
            )
        return findings