from __future__ import annotations

import json
from pathlib import Path

from ollama import Client

from configuration import PrototypeConfig
from knowledge_loader import load_knowledge_base
from schemas import IncidentInput, export_json_schemas


def main() -> None:
    config = PrototypeConfig()
    print(f"Configured model: {config.model}")
    print(f"Ollama host: {config.ollama_host}")

    knowledge = load_knowledge_base()
    print(f"Knowledge base loaded: {len(knowledge.documents)} files")
    print(f"Knowledge-base SHA-256: {knowledge.version_hash}")

    sample_path = Path("scenarios/development/DEV-001.json")
    sample = IncidentInput.model_validate_json(
        sample_path.read_text(encoding="utf-8")
    )
    print(f"Sample incident validated: {sample.incident_id}")

    export_json_schemas("schema_exports")
    print("JSON schemas exported.")

    client = Client(host=config.ollama_host)
    client.show(config.model)
    print(f"Ollama model is available: {config.model}")


if __name__ == "__main__":
    main()
