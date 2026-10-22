from __future__ import annotations

import argparse
import json
from pathlib import Path

from .evaluation import synthetic_demo


def main() -> None:
    parser = argparse.ArgumentParser(description="DDoS detection demo CLI")
    parser.add_argument("--demo", action="store_true", help="Run a synthetic evaluation demo")
    parser.add_argument("--output", type=str, default="data/demo_output.json", help="Path for demo output")
    args = parser.parse_args()

    if args.demo:
        result = synthetic_demo()
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"Synthetic demo results written to {output_path}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
