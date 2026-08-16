# Asteria Commerce AI-Assisted Incident Triage Prototype

This is the first bounded command-line implementation of the dissertation
prototype. It uses a local Ollama model and Pydantic JSON schemas.

It deliberately does not use:
- Tavily or live web search
- conversational memory
- autonomous agents
- command execution or remediation tools

## Windows setup

Open PowerShell in this project directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Confirm that Ollama is running and that the model exists:

```powershell
ollama list
python validate_setup.py
```

Run the first development scenario:

```powershell
python run_triage.py --input scenarios/development/DEV-001.json
```

To test another installed model:

```powershell
python run_triage.py --input scenarios/development/DEV-001.json --model gemma3:4b
```

A complete run record is written to `outputs/`, including:
- incident input
- raw model output
- parsed structured output
- validation errors
- model metadata
- end-to-end response time
- configuration
- knowledge-base hash

## Important

Do not modify the held-out evaluation scenarios after the prototype is
frozen. The `scenarios/evaluation/` directory is intentionally empty at
this stage.
