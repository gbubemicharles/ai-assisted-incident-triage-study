from __future__ import annotations

import os
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class PrototypeConfig:
    """Runtime configuration for the bounded hybrid triage prototype."""

    model: str = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")
    ollama_host: str = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    temperature: float = float(os.getenv("OLLAMA_TEMPERATURE", "0"))
    num_predict: int = int(os.getenv("OLLAMA_NUM_PREDICT", "1400"))
    num_ctx: int = int(os.getenv("OLLAMA_NUM_CTX", "12288"))

    prompt_version: str = "triage-system-v1.3"
    context_selection_version: str = "context-selection-v1.6"
    guardrail_version: str = "hybrid-guardrails-v1.7"
    input_schema_version: str = "incident-input-v1.2"
    output_schema_version: str = "triage-output-v1.2"

    def model_options(self) -> dict[str, int | float]:
        return {
            "temperature": self.temperature,
            "num_predict": self.num_predict,
            "num_ctx": self.num_ctx,
        }

    def as_dict(self) -> dict:
        return asdict(self)
