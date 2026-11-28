from core.cli import main


def test_cli_runs_end_to_end_and_writes_report(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("scanners:\n  gitleaks: {enabled: false}\n")
    out = tmp_path / "report.json"

    code = main([str(tmp_path), "--config", str(cfg), "--out", str(out)])

    assert code == 0
    assert out.exists()