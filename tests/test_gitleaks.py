import subprocess
from pathlib import Path

import pytest

from plugins.gitleaks import GitleaksScanner, ScannerError

SAMPLE = Path(__file__).parent / "data" / "gitleaks_sample.json"


def test_parse_real_report():
    findings = GitleaksScanner().parse(SAMPLE.read_text())
    assert len(findings) == 2
    assert {f.rule for f in findings} == {"aws-access-token", "generic-api-key"}
    assert all(f.category == "secret" for f in findings)
    assert "config.py:2" in {f.location for f in findings}


def test_parse_does_not_store_the_secret():
    findings = GitleaksScanner().parse(SAMPLE.read_text())
    assert "AKIAQ3ZXWV7TN4HJKP2M" not in str(findings)


def test_parse_empty_report():
    assert GitleaksScanner().parse("") == []
    assert GitleaksScanner().parse("[]") == []


def _fake_run(returncode, stderr=""):
    def fake(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, returncode, "", stderr)

    return fake


def test_run_exit_1_means_findings_not_crash(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", _fake_run(1))
    assert GitleaksScanner().run(str(tmp_path)) == "[]"


def test_run_exit_0_means_clean(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", _fake_run(0))
    assert GitleaksScanner().run(str(tmp_path)) == "[]"


def test_run_other_exit_code_raises(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", _fake_run(2, "boom"))
    with pytest.raises(ScannerError):
        GitleaksScanner().run(str(tmp_path))


def test_run_timeout_raises(monkeypatch, tmp_path):
    def fake(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(ScannerError):
        GitleaksScanner().run(str(tmp_path))