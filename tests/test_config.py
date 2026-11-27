from core.config import load_config


def test_loads_scanners_and_gate(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text(
        "scanners:\n"
        "  gitleaks: {enabled: true}\n"
        "  trivy: {enabled: false}\n"
        "gate:\n"
        "  fail_on: {critical: 2, high: 7}\n"
    )
    cfg = load_config(f)
    assert cfg.enabled_scanners() == ["gitleaks"]
    assert cfg.gate.fail_on == {"critical": 2, "high": 7}
    assert cfg.gate.fail_on_secret is True


def test_disabling_a_scanner_removes_it(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("scanners:\n  gitleaks: {enabled: false}\n")
    assert load_config(f).enabled_scanners() == []


def test_empty_file_gives_defaults(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("")
    cfg = load_config(f)
    assert cfg.enabled_scanners() == []
    assert cfg.gate.fail_on == {"critical": 1, "high": 5}


def test_project_config_file_is_valid():
    cfg = load_config("config.yaml")
    assert "gitleaks" in cfg.enabled_scanners()