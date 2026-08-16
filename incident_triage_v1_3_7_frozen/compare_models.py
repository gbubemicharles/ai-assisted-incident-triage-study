from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from configuration import PrototypeConfig
from triage_engine import TriageEngine, save_run_record

DEFAULT_MODELS = ["qwen2.5:7b", "qwen2.5:3b", "gemma3:4b"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare multiple Ollama models on one incident scenario."
    )
    parser.add_argument("--input", required=True, help="Path to incident JSON.")
    parser.add_argument("--models", nargs="+", default=DEFAULT_MODELS)
    parser.add_argument(
        "--output-dir",
        default="outputs/model_comparison",
        help="Directory for run records and comparison CSV.",
    )
    return parser.parse_args()


def safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    return cleaned.strip("._-") or "model"


def enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def extract_summary(result: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "model": result.config.model,
        "run_id": result.run_id,
        "status": result.status,
        "elapsed_seconds": round(result.elapsed_seconds, 3),
        "validation_error_count": len(result.validation_errors),
        "validation_errors": " | ".join(result.validation_errors),
        "severity": "",
        "category": "",
        "primary_affected_area": "",
        "additional_affected_areas": "",
        "primary_resolver_group": "",
        "coordination_groups": "",
        "initial_action_count": 0,
        "information_gap_count": 0,
        "selected_runbooks": ", ".join(result.selected_runbook_ids),
        "record_file": "",
    }

    output = result.output
    if output is None:
        return row

    row.update(
        {
            "severity": enum_value(output.severity.level),
            "category": enum_value(output.incident_category.code),
            "primary_affected_area": enum_value(output.affected_area.primary_area_id),
            "additional_affected_areas": ", ".join(
                enum_value(item) for item in output.affected_area.additional_area_ids
            ),
            "primary_resolver_group": enum_value(
                output.routing.primary_resolver_group_id
            ),
            "coordination_groups": ", ".join(
                enum_value(item) for item in output.routing.coordination_group_ids
            ),
            "initial_action_count": len(output.initial_actions),
            "information_gap_count": len(output.information_gaps),
        }
    )
    return row


def write_error_record(
    output_dir: Path,
    incident_id: str,
    model: str,
    error: Exception,
) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = output_dir / (
        f"{incident_id}_{safe_name(model)}_{timestamp}_execution_error.json"
    )
    record = {
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "incident_id": incident_id,
        "model": model,
        "status": "execution_error",
        "error_type": type(error).__name__,
        "error_message": str(error),
    }
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return path


def write_comparison_csv(
    rows: list[dict[str, Any]], output_dir: Path, incident_id: str
) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = output_dir / f"{incident_id}_model_comparison_{timestamp}.csv"
    fieldnames = [
        "model",
        "run_id",
        "status",
        "elapsed_seconds",
        "validation_error_count",
        "validation_errors",
        "severity",
        "category",
        "primary_affected_area",
        "additional_affected_areas",
        "primary_resolver_group",
        "coordination_groups",
        "initial_action_count",
        "information_gap_count",
        "selected_runbooks",
        "record_file",
    ]
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return path


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        incident_data = json.loads(input_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"Input file not found: {input_path}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"Invalid input JSON: {exc}", file=sys.stderr)
        return 1

    incident_id = str(incident_data.get("incident_id", "unknown_incident"))
    base_config = PrototypeConfig()
    rows: list[dict[str, Any]] = []

    print(f"Incident: {incident_id}")
    print(f"Models: {', '.join(args.models)}")
    print(f"Output directory: {output_dir.resolve()}")

    for index, model in enumerate(args.models, start=1):
        print(f"\n[{index}/{len(args.models)}] Running model: {model}")
        try:
            config = replace(base_config, model=model)
            engine = TriageEngine(config=config)
            result = engine.triage(incident_data)
            record_path = save_run_record(result, output_dir)

            row = extract_summary(result)
            row["record_file"] = str(record_path)
            rows.append(row)

            print(
                f"Completed: status={result.status}, "
                f"time={result.elapsed_seconds:.3f}s, "
                f"record={record_path.name}"
            )
            for validation_error in result.validation_errors:
                print(f"  Validation error: {validation_error}")

        except Exception as exc:
            error_path = write_error_record(
                output_dir, incident_id, model, exc
            )
            rows.append(
                {
                    "model": model,
                    "run_id": "",
                    "status": "execution_error",
                    "elapsed_seconds": "",
                    "validation_error_count": 1,
                    "validation_errors": f"{type(exc).__name__}: {exc}",
                    "severity": "",
                    "category": "",
                    "primary_affected_area": "",
                    "additional_affected_areas": "",
                    "primary_resolver_group": "",
                    "coordination_groups": "",
                    "initial_action_count": 0,
                    "information_gap_count": 0,
                    "selected_runbooks": "",
                    "record_file": str(error_path),
                }
            )
            print(f"Model failed: {type(exc).__name__}: {exc}")
            print(f"Error record: {error_path.name}")

    csv_path = write_comparison_csv(rows, output_dir, incident_id)
    print("\nComparison complete.")
    print(f"CSV saved to: {csv_path}")

    completed = sum(row["status"] in {"valid", "invalid"} for row in rows)
    return 0 if completed else 2


if __name__ == "__main__":
    raise SystemExit(main())
