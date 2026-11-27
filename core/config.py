from pathlib import Path

import yaml
from pydantic import BaseModel


class ScannerConfig(BaseModel):
    enabled: bool = True


class GateConfig(BaseModel):
    fail_on: dict[str, int] = {"critical": 1, "high": 5}
    fail_on_secret: bool = True


class Config(BaseModel):
    scanners: dict[str, ScannerConfig] = {}
    gate: GateConfig = GateConfig()

    def enabled_scanners(self) -> list[str]:
        return [name for name, cfg in self.scanners.items() if cfg.enabled]


def load_config(path: str | Path) -> Config:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return Config(**data)