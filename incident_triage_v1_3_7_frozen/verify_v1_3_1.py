from __future__ import annotations

from configuration import PrototypeConfig
from guardrails import apply_guardrails


def main() -> None:
    config = PrototypeConfig()
    print("Prompt version:", config.prompt_version)
    print("Guardrail version:", config.guardrail_version)
    print("Configured model:", config.model)
    print("Num predict:", config.num_predict)
    print("Guardrail import: OK", apply_guardrails.__name__)


if __name__ == "__main__":
    main()
