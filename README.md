# AI-Assisted Incident Triage Study

This repository contains the frozen prototype and official evaluation artefacts developed for the MSc dissertation:

**Design and Evaluation of an AI-Assisted Incident Triage Framework for Cloud Operations Teams: A Prototype-Based Study**

The research examined whether a bounded, locally hosted language-model prototype could organise incident evidence and produce structured initial-triage outputs under controlled conditions. The prototype remained advisory and could not execute commands, modify infrastructure, initiate remediation, assign operational queues or establish a definitive root cause.

## Repository contents

```text
ai-assisted-incident-triage-study/
├── incident_triage_v1_3_7_frozen/
│   ├── evaluation/          # Evaluation-supporting code
│   ├── freeze_metadata/     # Frozen release record and SHA-256 manifest
│   ├── knowledge_base/      # Controlled operational knowledge
│   ├── outputs/             # Formative regression records
│   ├── scenarios/           # Synthetic development scenarios
│   ├── schema_exports/      # Exported JSON schemas
│   └── *.py                 # Prototype source code
└── incident_triage_v1_3_7_evaluation_study/
    ├── logs/                # Execution ledgers and pre-execution checks
    ├── outputs/             # Twelve primary and twelve repeat records
    ├── protocol/            # Evaluation protocol and metric definitions
    ├── reference_outcomes/  # Predefined evaluation outcomes
    ├── scenario_matrix/     # Scenario coverage matrix
    ├── scenarios/           # Held-out synthetic incidents
    ├── scoring/             # Evaluation scoring artefacts
    ├── sealed_inputs/       # Sealed scenarios and reference outcomes
    └── sealed_results/      # Primary and repeat completion records
```

## Evaluated prototype

| Item | Frozen value |
|---|---|
| Prototype version | 1.3.7 |
| Language model | qwen2.5:7b |
| Model serving | Ollama |
| Prompt version | triage-system-v1.3 |
| Context-selection version | v1.6 |
| Guardrail version | v1.7 |
| Input schema | v1.2 |
| Output schema | v1.2 |
| Temperature | 0.0 |
| Primary evaluation runs | 12 |
| Predetermined repeat runs | 12 |

The frozen knowledge-base SHA-256 digest was:

```text
aec7e81447a14bf90f2d1bcab03d11540d79a92d9d681e123bf057c67a52e099
```

## Local setup

The prototype requires Python and a locally running Ollama installation.

From the repository root:

```powershell
cd incident_triage_v1_3_7_frozen
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
ollama pull qwen2.5:7b
python validate_setup.py
```

Run a development scenario:

```powershell
python run_triage.py --input scenarios/development/DEV-001.json
```

A self-contained JSON run record will be written to the configured output directory.

## Evaluation evidence

The evaluation-study package contains the preserved records from:

- 12 primary runs used for effectiveness assessment;
- 12 predetermined repeat runs used only for stability assessment.

The reference outcomes were kept separate from the prototype during execution. SHA-256 manifests and phase-completion records support verification of the frozen inputs, primary outputs and repeat outputs.

## Continuous integration

Repository-level continuous integration checks will validate the Python source, structured data, frozen knowledge-base digest and deterministic components. The GitHub-hosted checks will not invoke the local language model because Ollama and `qwen2.5:7b` are external runtime dependencies.

## Limitations

This is a controlled proof-of-concept research artefact. It was evaluated using synthetic incidents, a compact fictional operational environment, one locally hosted model and no human participants or production systems. It should not be treated as a production incident-management system.

## Version

The dissertation artefact will be identified by the Git tag and GitHub Release:

```text
v1.3.7
```