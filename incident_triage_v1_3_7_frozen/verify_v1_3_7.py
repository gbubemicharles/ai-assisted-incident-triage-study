from configuration import PrototypeConfig
from context_builder import select_operational_knowledge
from guardrails import apply_guardrails
from validation import validate_triage_output

config = PrototypeConfig()

print(f"Prompt version: {config.prompt_version}")
print(f"Context selection version: {config.context_selection_version}")
print(f"Guardrail version: {config.guardrail_version}")
print(f"Configured model: {config.model}")
print(f"Num predict: {config.num_predict}")
print(f"Context selector import: OK {select_operational_knowledge.__name__}")
print(f"Guardrail import: OK {apply_guardrails.__name__}")
print(f"Validator import: OK {validate_triage_output.__name__}")
