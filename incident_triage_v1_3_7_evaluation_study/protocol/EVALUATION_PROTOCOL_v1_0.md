# Held-Out Evaluation Protocol

## Study

**Title:** Design and Evaluation of an AI-Assisted Incident Triage Framework for Cloud Operations Teams: A Prototype-Based Study

**Prototype:** v1.3.7

**Protocol version:** 1.0

## Purpose

The held-out evaluation assesses the frozen prototype's ability to:

1. produce structurally valid incident-triage outputs;
2. classify incident severity and category accurately;
3. identify the affected technical area;
4. recommend the correct resolver group and coordination requirements;
5. recommend safe, relevant and evidence-supported initial actions;
6. preserve material information gaps and uncertainty;
7. avoid unsupported causal claims and prohibited remediation;
8. improve raw model decisions through deterministic guardrails; and
9. produce stable decisions across predetermined repeat executions.

## Evaluation set

The evaluation contains 12 held-out scenarios:

- EVAL-001 to EVAL-010: two core scenarios for each supported incident category;
- EVAL-011 and EVAL-012: ambiguity and decision-boundary scenarios.

The scenario inputs must be materially distinct from the formative development scenarios.

## Runs

Each scenario receives:

- one official primary execution; and
- one predetermined repeat execution.

This produces:

- 12 primary runs;
- 12 repeat runs;
- 24 total executions.

The primary runs determine the principal effectiveness results. Repeat runs assess stability and must not replace unsuccessful primary results.

## Execution order

Primary executions will be performed in the fixed order EVAL-001 to EVAL-012.

Repeat executions will then be performed in the same fixed order.

No selective rerun is permitted because an output receives a poor score.

A replacement execution is allowed only after a documented external technical interruption, such as process termination, power loss, unavailable Ollama service before generation, or failed file writing. A structurally invalid prototype output is an evaluation result and is not grounds for replacement.

## Frozen candidate

The following must remain unchanged throughout evaluation:

- model: qwen2.5:7b;
- Ollama model ID: 845dbda0ea48;
- prompt: triage-system-v1.3;
- context selection: context-selection-v1.6;
- guardrails: hybrid-guardrails-v1.7;
- input schema: incident-input-v1.2;
- output schema: triage-output-v1.2;
- temperature: 0.0;
- num_predict: 1400;
- num_ctx: 12288; and
- frozen knowledge-base hash.

No prompt, code, knowledge-base, schema, guardrail or runtime-configuration change is permitted after the evaluation design is sealed.

## Reference-first assessment

A reference outcome will be written for every scenario before any scenario is executed.

Each reference outcome will define:

- required summary facts;
- prohibited or unsupported claims;
- expected severity and provisional status;
- expected category and provisional status;
- expected primary and additional affected areas;
- expected resolver and coordination groups;
- required and acceptable action identifiers;
- expected runbook;
- prohibited recommendations;
- expected information gaps;
- advisory-only status; and
- definitive-root-cause status.

Reference outcomes will be sealed using SHA-256 before execution. They must not be revised after outputs have been observed.

## Outputs assessed

The same scoring rubric will be applied to:

1. `model_output`, representing the parsed model decision before deterministic guardrails; and
2. `output`, representing the final guarded framework output.

The final guarded output is the principal evaluation result.

Guardrail effect will be reported as:

- final score minus raw-model score;
- incorrect raw decisions corrected by guardrails;
- correct raw decisions made incorrect by guardrails; and
- safety violations removed, retained or introduced.

## Quantitative reporting

Results will include:

- counts and percentages;
- exact-match accuracy;
- set precision, recall and F1 where applicable;
- mean, median, minimum and maximum composite scores;
- raw-versus-final score differences;
- per-scenario results;
- category-level results;
- severity-level results; and
- primary-versus-repeat stability.

Because the held-out set is purposive and contains 12 scenarios, analysis will be primarily descriptive. The study will not claim population-level generalisation from this sample.

## Stability

Primary and repeat final outputs will be compared using:

- exact agreement for severity, category, primary area and primary resolver;
- agreement for provisional-status fields;
- Jaccard similarity for additional affected areas, coordination groups, common action IDs and runbook IDs; and
- agreement for advisory-only and definitive-root-cause flags.

Differences in harmless wording alone will not be treated as decision instability.

## Structural failures

Structural validity is reported separately.

Where a required structured output is absent or invalid, unavailable schema-dependent scoring components receive zero. The failure record must be preserved and must not be manually repaired.

## Research integrity

All official inputs, reference outcomes, outputs, scores, manifests and execution logs must be retained.

No output may be manually edited.

Any prototype modification after sealing creates a new prototype version and prevents direct comparison with the v1.3.7 results.
