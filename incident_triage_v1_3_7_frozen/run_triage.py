from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from configuration import PrototypeConfig
from triage_engine import TriageEngine, save_run_record


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run one bounded cloud incident-triage assessment."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to a JSON incident file.",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Optional Ollama model override, for example qwen2.5:7b.",
    )
    parser.add_argument(
        "--output-dir",
        default="outputs",
        help="Directory for the complete run record.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)

    try:
        incident_data = json.loads(input_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"Input file not found: {input_path}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"Invalid input JSON: {exc}", file=sys.stderr)
        return 1

    config = PrototypeConfig()
    if args.model:
        config = PrototypeConfig(
            model=args.model,
            ollama_host=config.ollama_host,
            temperature=config.temperature,
            num_predict=config.num_predict,
            num_ctx=config.num_ctx,
        )

    try:
        engine = TriageEngine(config=config)
        result = engine.triage(incident_data)
        saved_path = save_run_record(result, args.output_dir)
    except Exception as exc:
        print(f"Prototype execution failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result.as_record(), indent=2, ensure_ascii=False))
    print(f"\nSaved complete run record to: {saved_path}")

    return 0 if result.status == "valid" else 2


if __name__ == "__main__":
    raise SystemExit(main())
