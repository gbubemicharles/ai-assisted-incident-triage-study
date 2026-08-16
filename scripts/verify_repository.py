from __future__ import annotations

import ast
import csv
import hashlib
import json
import sys
import tokenize
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FROZEN = ROOT / "incident_triage_v1_3_7_frozen"
STUDY = ROOT / "incident_triage_v1_3_7_evaluation_study"

EXPECTED_KNOWLEDGE_HASH = (
    "aec7e81447a14bf90f2d1bcab03d11540d79a92d9d681e123bf057c67a52e099"
)

KNOWLEDGE_FILES = (
    "severity_matrix.json",
    "incident_categories.json",
    "services.json",
    "resolver_groups.json",
    "dependencies.json",
    "ownership_map.json",
    "runbooks.json",
)

errors: list[str] = []


def record_error(message: str) -> None:
    errors.append(message)
    print(f"ERROR: {message}")


def check_required_structure() -> None:
    required_paths = (
        FROZEN,
        FROZEN / "freeze_metadata",
        FROZEN / "knowledge_base",
        STUDY,
        STUDY / "logs",
        STUDY / "outputs" / "primary",
        STUDY / "outputs" / "repeat",
        STUDY / "protocol",
        STUDY / "reference_outcomes",
        STUDY / "scenario_matrix",
        STUDY / "scenarios",
        STUDY / "sealed_inputs",
        STUDY / "sealed_results",
    )

    for path in required_paths:
        if not path.exists():
            record_error(
                f"Required path is missing: {path.relative_to(ROOT)}"
            )


def validate_python_syntax() -> int:
    checked = 0

    for path in sorted(FROZEN.rglob("*.py")):
        checked += 1

        try:
            with tokenize.open(path) as source_file:
                source = source_file.read()

            ast.parse(source, filename=str(path))

        except (SyntaxError, UnicodeError) as exc:
            record_error(
                f"Invalid Python file {path.relative_to(ROOT)}: {exc}"
            )

    return checked


def validate_json_files() -> int:
    checked = 0

    for directory in (FROZEN, STUDY):
        if not directory.exists():
            continue

        for path in sorted(directory.rglob("*.json")):
            checked += 1

            try:
                json.loads(path.read_text(encoding="utf-8-sig"))

            except (UnicodeError, json.JSONDecodeError) as exc:
                record_error(
                    f"Invalid JSON in {path.relative_to(ROOT)}: {exc}"
                )

    return checked


def verify_frozen_manifest() -> int:
    manifest = (
        FROZEN
        / "freeze_metadata"
        / "FILE_MANIFEST_SHA256.csv"
    )

    if not manifest.exists():
        record_error(
            f"Frozen manifest is missing: {manifest.relative_to(ROOT)}"
        )
        return 0

    checked = 0

    with manifest.open(
        encoding="utf-8-sig",
        newline="",
    ) as handle:
        reader = csv.DictReader(handle)

        required_columns = {"path", "bytes", "sha256"}

        if not required_columns.issubset(reader.fieldnames or []):
            record_error(
                "Frozen manifest does not contain the required columns"
            )
            return 0

        for row in reader:
            checked += 1
            relative_path = row["path"]
            target = FROZEN / relative_path

            if not target.is_file():
                record_error(
                    f"Manifest file is missing: "
                    f"{target.relative_to(ROOT)}"
                )
                continue

            content = target.read_bytes()

            try:
                expected_size = int(row["bytes"])
            except ValueError:
                record_error(
                    f"Invalid byte count for {relative_path}"
                )
                continue

            if len(content) != expected_size:
                record_error(
                    f"Byte-count mismatch for {relative_path}: "
                    f"expected {expected_size}, "
                    f"found {len(content)}"
                )

            actual_hash = hashlib.sha256(content).hexdigest()
            expected_hash = row["sha256"].strip().lower()

            if actual_hash.lower() != expected_hash:
                record_error(
                    f"SHA-256 mismatch for frozen file: "
                    f"{relative_path}"
                )

    return checked


def verify_knowledge_hash() -> None:
    knowledge_directory = FROZEN / "knowledge_base"
    digest = hashlib.sha256()

    for filename in KNOWLEDGE_FILES:
        path = knowledge_directory / filename

        if not path.is_file():
            record_error(
                f"Required knowledge file is missing: "
                f"{path.relative_to(ROOT)}"
            )
            return

        digest.update(filename.encode("utf-8"))
        digest.update(path.read_bytes())

    actual_hash = digest.hexdigest()

    if actual_hash != EXPECTED_KNOWLEDGE_HASH:
        record_error(
            "Knowledge-base hash mismatch: "
            f"expected {EXPECTED_KNOWLEDGE_HASH}, "
            f"found {actual_hash}"
        )


def verify_evaluation_counts() -> None:
    expected_counts = {
        STUDY / "scenarios": (
            "EVAL-*.json",
            12,
            "evaluation scenarios",
        ),
        STUDY / "reference_outcomes": (
            "EVAL-*_reference_outcome.json",
            12,
            "reference outcomes",
        ),
        STUDY / "outputs" / "primary": (
            "EVAL-*.json",
            12,
            "primary run records",
        ),
        STUDY / "outputs" / "repeat": (
            "EVAL-*.json",
            12,
            "repeat run records",
        ),
    }

    for directory, details in expected_counts.items():
        pattern, expected, label = details

        if not directory.exists():
            continue

        actual = len(list(directory.glob(pattern)))

        if actual != expected:
            record_error(
                f"Expected {expected} {label}; found {actual}"
            )


def main() -> int:
    print(
        "Validating repository structure "
        "and preserved research artefacts..."
    )

    check_required_structure()
    python_count = validate_python_syntax()
    json_count = validate_json_files()
    manifest_count = verify_frozen_manifest()
    verify_knowledge_hash()
    verify_evaluation_counts()

    if errors:
        print(
            f"\nValidation failed with {len(errors)} error(s)."
        )
        return 1

    print(
        "\nValidation passed: "
        f"{python_count} Python files, "
        f"{json_count} JSON files and "
        f"{manifest_count} frozen-manifest entries checked."
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())