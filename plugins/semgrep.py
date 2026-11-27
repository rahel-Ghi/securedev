import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from core.finding import Finding, Severity
from core.plugin import Scanner
from plugins.gitleaks import ScannerError

IMAGE = "semgrep/semgrep:1.186.0"

SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SemgrepScanner(Scanner):
    name = "semgrep"

    def run(self, target: str, timeout: int = 600) -> str:
        with tempfile.TemporaryDirectory() as out_dir:
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{Path(target).resolve()}:/src",
                "-v", f"{out_dir}:/out",
                IMAGE, "semgrep", "scan",
                "--config", "p/python",
                "--json", "--output", "/out/report.json",
                "--metrics=off", "--quiet",
                "--exclude", ".venv",
                "--exclude", "samples",
                "/src",
            ]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout
                )
            except subprocess.TimeoutExpired:
                raise ScannerError(f"semgrep timed out after {timeout}s")
            except FileNotFoundError:
                raise ScannerError("docker command not found")

            # Without --error, Semgrep exits 0 even when it finds issues
            if result.returncode != 0:
                raise ScannerError(
                    f"semgrep failed (exit {result.returncode}): "
                    f"{result.stderr.strip()[-300:]}"
                )

            report = Path(out_dir) / "report.json"
            return report.read_text(encoding="utf-8") if report.exists() else "{}"

    def parse(self, raw: str) -> list[Finding]:
        if not raw.strip():
            return []
        findings = []
        for item in json.loads(raw).get("results") or []:
            path = item["path"]
            if path.startswith("/src/"):
                path = path[len("/src/"):]
            location = f"{path}:{item['start']['line']}"
            rule = item["check_id"]
            sev = item.get("extra", {}).get("severity", "INFO")
            key = f"code|{location}|{rule}"
            findings.append(
                Finding(
                    tool=self.name,
                    rule=rule,
                    category="code",
                    severity=SEVERITY_MAP.get(sev, Severity.LOW),
                    location=location,
                    fingerprint=hashlib.sha256(key.encode()).hexdigest()[:16],
                )
            )
        return findings