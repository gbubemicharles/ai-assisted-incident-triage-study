from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ollama import Client
from pydantic import ValidationError

from configuration import PrototypeConfig
from context_builder import SelectedKnowledge, select_operational_knowledge
from guardrails import GuardrailChange, apply_guardrails
from knowledge_loader import KnowledgeBundle, load_knowledge_base
from prompts import SYSTEM_PROMPT, build_user_prompt
from schemas import IncidentInput, TriageOutput
from validation import validate_triage_output


@dataclass
class TriageRunResult:
    run_id: str
    status: str
    incident: IncidentInput
    model_output: TriageOutput | None
    output: TriageOutput | None
    raw_output: str
    guardrail_changes: list[GuardrailChange]
    validation_errors: list[str]
    elapsed_seconds: float
    model_metadata: dict[str, Any]
    config: PrototypeConfig
    knowledge_hash: str
    selected_knowledge_refs: list[str]
    selected_runbook_ids: list[str]

    def as_record(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
            "status": self.status,
            "incident": self.incident.model_dump(mode="json"),
            "model_output": (
                self.model_output.model_dump(mode="json")
                if self.model_output is not None
                else None
            ),
            "output": self.output.model_dump(mode="json") if self.output else None,
            "raw_output": self.raw_output,
            "guardrail_changes": [item.as_dict() for item in self.guardrail_changes],
            "validation_errors": self.validation_errors,
            "elapsed_seconds": self.elapsed_seconds,
            "model_metadata": self.model_metadata,
            "configuration": self.config.as_dict(),
            "knowledge_base_hash": self.knowledge_hash,
            "selected_knowledge_refs": self.selected_knowledge_refs,
            "selected_runbook_ids": self.selected_runbook_ids,
        }


def _read_attr_or_key(obj: Any, name: str, default: Any = None) -> Any:
    if hasattr(obj, name):
        return getattr(obj, name)
    if isinstance(obj, dict):
        return obj.get(name, default)
    return default


def _response_content(response: Any) -> str:
    message = _read_attr_or_key(response, "message")
    content = _read_attr_or_key(message, "content")
    if not isinstance(content, str):
        raise RuntimeError("Ollama response did not contain textual message content.")
    return content


def _response_metadata(response: Any) -> dict[str, Any]:
    names = (
        "model", "created_at", "done", "done_reason", "total_duration",
        "load_duration", "prompt_eval_count", "prompt_eval_duration",
        "eval_count", "eval_duration",
    )
    return {
        name: _read_attr_or_key(response, name)
        for name in names
        if _read_attr_or_key(response, name) is not None
    }


class TriageEngine:
    def __init__(
        self,
        config: PrototypeConfig | None = None,
        knowledge_directory: str | Path = "knowledge_base",
    ) -> None:
        self.config = config or PrototypeConfig()
        self.knowledge: KnowledgeBundle = load_knowledge_base(knowledge_directory)
        self.client = Client(host=self.config.ollama_host)

    def triage(self, incident_data: dict[str, Any] | IncidentInput) -> TriageRunResult:
        incident = (
            incident_data
            if isinstance(incident_data, IncidentInput)
            else IncidentInput.model_validate(incident_data)
        )
        selected: SelectedKnowledge = select_operational_knowledge(
            incident, self.knowledge
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_prompt(incident, selected)},
        ]

        started = time.perf_counter()
        response = self.client.chat(
            model=self.config.model,
            messages=messages,
            format=TriageOutput.model_json_schema(),
            stream=False,
            options=self.config.model_options(),
        )
        elapsed = time.perf_counter() - started

        raw_output = _response_content(response)
        metadata = _response_metadata(response)
        errors: list[str] = []
        model_output: TriageOutput | None = None
        final_output: TriageOutput | None = None
        guardrail_changes: list[GuardrailChange] = []

        try:
            model_output = TriageOutput.model_validate_json(raw_output)
        except ValidationError as exc:
            errors.append(f"Output-schema validation failed: {exc}")
        except ValueError as exc:
            errors.append(f"Output JSON could not be parsed: {exc}")

        if model_output is not None:
            try:
                final_output, guardrail_changes = apply_guardrails(
                    incident=incident,
                    model_output=model_output,
                    selected=selected,
                    knowledge=self.knowledge,
                )
            except Exception as exc:
                errors.append(f"Guardrail processing failed: {type(exc).__name__}: {exc}")

        if final_output is not None:
            errors.extend(
                validate_triage_output(incident, final_output, selected.allowed_refs)
            )

        status = "valid" if final_output is not None and not errors else "invalid"

        return TriageRunResult(
            run_id=str(uuid.uuid4()),
            status=status,
            incident=incident,
            model_output=model_output,
            output=final_output,
            raw_output=raw_output,
            guardrail_changes=guardrail_changes,
            validation_errors=errors,
            elapsed_seconds=elapsed,
            model_metadata=metadata,
            config=self.config,
            knowledge_hash=self.knowledge.version_hash,
            selected_knowledge_refs=sorted(selected.allowed_refs),
            selected_runbook_ids=list(selected.selected_runbook_ids),
        )


def save_run_record(
    result: TriageRunResult,
    output_directory: str | Path = "outputs",
) -> Path:
    output_dir = Path(output_directory)
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{result.incident.incident_id}_{result.run_id}_{result.status}.json"
    path = output_dir / filename
    path.write_text(
        json.dumps(result.as_record(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return path
