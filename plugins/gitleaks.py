import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from core.finding import Finding, Severity
from core.plugin import Scanner

IMAGE = "zricethezav/gitleaks:v8.30.1"


class ScannerError(Exception):
    """Raised when a scanner fails or times out."""


class GitleaksScanner(Scanner):
    name = "gitleaks"

    def run(self, target: str, timeout: int = 120) -> str:
        with tempfile.TemporaryDirectory() as out_dir:
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{Path(target).resolve()}:/repo",
                "-v", f"{out_dir}:/out",
                IMAGE, "detect",
                "--source", "/repo",
                "--report-format", "json",
                "--report-path", "/out/report.json",
                "--no-banner",
            ]
            if (Path(target) / ".gitleaks.toml").exists():
                cmd += ["--config", "/repo/.gitleaks.toml"]

            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout
                )
            except subprocess.TimeoutExpired:
                raise ScannerError(f"gitleaks timed out after {timeout}s")
            except FileNotFoundError:
                raise ScannerError("docker command not found")

            # Exit code 0 = clean, 1 = leaks found, anything else = failure
            if result.returncode not in (0, 1):
                raise ScannerError(
                    f"gitleaks failed (exit {result.returncode}): "
                    f"{result.stderr.strip()[-300:]}"
                )

            report = Path(out_dir) / "report.json"
            return report.read_text(encoding="utf-8") if report.exists() else "[]"

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