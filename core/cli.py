import argparse
import sys
from pathlib import Path

from core.config import load_config
from core.orchestrator import run_scan


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="securedev")
    p.add_argument("target")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--out", default="results/report.json")
    args = p.parse_args(argv)

    result = run_scan(args.target, load_config(args.config))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(result.model_dump_json(indent=2), encoding="utf-8")

    print(f"findings: {len(result.findings)}, failures: {len(result.failures)}")
    print("GATE:", "PASSED" if result.gate.passed else "FAILED")
    for reason in result.gate.reasons:
        print(" -", reason)
    return 0 if result.gate.passed else 1


if __name__ == "__main__":
    sys.exit(main())