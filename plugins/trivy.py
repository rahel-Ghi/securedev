import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from core.finding import Finding, Severity
from core.plugin import Scanner
from plugins.gitleaks import ScannerError

IMAGE = "aquasec/trivy:0.76.1"

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


class TrivyScanner(Scanner):
    name = "trivy"

    def run(self, target: str, timeout: int = 600) -> str:
        with tempfile.TemporaryDirectory() as out_dir:
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{Path(target).resolve()}:/target",
                "-v", f"{out_dir}:/out",
                "-v", "securedev-trivy-cache:/root/.cache",
                IMAGE, "fs",
                "--format", "json",
                "--output", "/out/report.json",
                "--skip-dirs", "/target/.venv",
                "--skip-dirs", "/target/samples",
                "--quiet",
                "/target",
            ]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout
                )
            except subprocess.TimeoutExpired:
                raise ScannerError(f"trivy timed out after {timeout}s")
            except FileNotFoundError:
                raise ScannerError("docker command not found")

            # Without --exit-code, Trivy exits 0 even when it finds issues
            if result.returncode != 0:
                raise ScannerError(
                    f"trivy failed (exit {result.returncode}): "
                    f"{result.stderr.strip()[-300:]}"
                )

            report = Path(out_dir) / "report.json"
            return report.read_text(encoding="utf-8") if report.exists() else "{}"

    def parse(self, raw: str) -> list[Finding]:
        if not raw.strip():
            return []
        findings = []
        for res in json.loads(raw).get("Results") or []:
            for vuln in res.get("Vulnerabilities") or []:
                vuln_id = vuln["VulnerabilityID"]
                location = (
                    f"{res['Target']}:{vuln['PkgName']}@{vuln['InstalledVersion']}"
                )
                key = f"dependency|{location}|{vuln_id}"
                findings.append(
                    Finding(
                        tool=self.name,
                        rule=vuln_id,
                        category="dependency",
                        severity=SEVERITY_MAP.get(
                            vuln.get("Severity", "UNKNOWN"), Severity.INFO
                        ),
                        location=location,
                        cve=vuln_id if vuln_id.startswith("CVE-") else None,
                        fingerprint=hashlib.sha256(key.encode()).hexdigest()[:16],
                    )
                )
        return findings