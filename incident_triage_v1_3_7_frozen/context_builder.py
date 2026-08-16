from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from knowledge_loader import KnowledgeBundle
from schemas import ImpactScope, IncidentInput


@dataclass(frozen=True)
class SelectedKnowledge:
    payload: dict[str, Any]
    allowed_refs: frozenset[str]
    selected_runbook_ids: tuple[str, ...]

    def prompt_payload(self) -> str:
        return json.dumps(
            self.payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


RUNBOOK_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("RB-008", ("external payment", "payment gateway", "authorisation", "http 503")),
    ("RB-009", ("expired credential", "invalid credential", "missing credential", "expired token", "invalid token", "missing token", "expired certificate", "certificate expired", "authentication configuration failure")),
    ("RB-005", ("dns", "firewall", "route", "routing", "load balancer", "load-balancing")),
    ("RB-007", ("database latency", "query latency", "locking", "contention", "connection saturation")),
    ("RB-006", ("database unavailable", "database connection", "database connectivity", "cannot connect to the database")),
    ("RB-010", ("message broker unavailable", "message broker failure", "broker unavailable", "broker failure", "queue backlog", "queue depth", "consumer delay")),
    ("RB-011", ("object storage", "web asset", "assets fail", "storage access")),
    ("RB-004", ("compute node", "compute cluster unavailable", "compute cluster failure", "host unavailable", "node unavailable")),
    ("RB-003", ("exception", "stack trace", "crash", "http 500", "deployment")),
    ("RB-002", ("latency", "slow", "degraded", "degradation", "throughput", "timeout")),
    ("RB-001", ("unavailable", "outage", "inaccessible", "all requests failing")),
    ("RB-012", ("multiple services", "multi-service", "ownership unclear", "common cause not established")),
)


ISSUE_SIGNAL_TERMS = (
    "unavailable",
    "failure",
    "failing",
    "failed",
    "error",
    "timeout",
    "latency",
    "slow",
    "degraded",
    "backlog",
    "contention",
    "saturation",
    "expired",
    "invalid",
    "missing",
    "packet loss",
    "unreachable",
    "exception",
    "crash",
    "inaccessible",
)

HEALTH_ONLY_TERMS = (
    "healthy",
    "operating normally",
    "within its normal range",
    "no issues",
    "not affected",
    "unaffected",
)

NEGATIVE_HEALTH_PATTERNS = (
    r"^\s*no\b.*\bhas been observed[.]?\s*$",
    r"\bno failed (orders|messages|notifications|transactions|requests)\b",
    r"\bno duplicate (orders|messages|transactions)\b",
    r"\bno customer-facing outage\b",
    r"\bno data loss\b",
    r"\bno security exposure\b",
    r"\bcontinue(?:s)? to (?:operate|process|function) normally\b",
)


def _contains_term(text: str, term: str) -> bool:
    """Match operational terms as words or phrases, avoiding substring collisions."""
    return re.search(
        rf"(?<![a-z0-9]){re.escape(term.lower())}(?![a-z0-9])",
        text.lower(),
    ) is not None


def _has_issue_signal(statement: str) -> bool:
    return any(_contains_term(statement, term) for term in ISSUE_SIGNAL_TERMS)


def _is_health_only_statement(statement: str) -> bool:
    negative_health = any(
        re.search(pattern, statement, flags=re.IGNORECASE)
        for pattern in NEGATIVE_HEALTH_PATTERNS
    )
    return negative_health or (
        any(_contains_term(statement, term) for term in HEALTH_ONLY_TERMS)
        and not _has_issue_signal(statement)
    )


def _has_direct_application_failure_evidence(
    incident: IncidentInput,
) -> bool:
    """Detect direct application exceptions or processing failures."""
    evidence_text = " ".join(
        f"{item.source_name} {item.observation}"
        for item in incident.technical_evidence
        if not _is_health_only_statement(item.observation)
    ).lower()
    return (
        re.search(r"\b[a-z0-9_]*exception\b", evidence_text) is not None
        or any(
            term in evidence_text
            for term in (
                "stack trace",
                "application crash",
                "runtime failure",
                "failed to render",
                "rendering error",
                "http 500",
            )
        )
    )


def _runbook_text(incident: IncidentInput) -> str:
    parts = [
        incident.title,
        incident.alert_or_symptom,
        incident.service_impact.user_impact_description,
        *incident.reported_unknowns,
    ]

    # Architecture-only context must not activate a runbook merely because a
    # component name is mentioned. Include it only when it carries an issue signal.
    for statement in incident.environmental_context:
        if _has_issue_signal(statement) and not _is_health_only_statement(statement):
            parts.append(statement)

    for item in incident.technical_evidence:
        if not _is_health_only_statement(item.observation):
            parts.append(item.observation)

    parts.extend(change.description for change in incident.recent_changes)

    for statement in incident.additional_context:
        if _has_issue_signal(statement) and not _is_health_only_statement(statement):
            parts.append(statement)

    return " ".join(parts).lower()


def _select_runbook_ids(incident: IncidentInput) -> tuple[str, ...]:
    text = _runbook_text(incident)
    selected: list[str] = []

    multi_service = (
        incident.service_impact.impact_scope == ImpactScope.MULTI_SERVICE
        or len(incident.reported_affected_service_ids) > 1
    )
    if multi_service:
        # Multi-service coordination is a structural condition, not merely a keyword.
        selected.append("RB-012")

    evidence_text = " ".join(
        f"{item.source_name} {item.observation}"
        for item in incident.technical_evidence
        if not _is_health_only_statement(item.observation)
    ).lower()
    application_exception_condition = (
        re.search(r"\b[a-z0-9_]*exception\b", evidence_text) is not None
        or any(
            term in evidence_text
            for term in (
                "stack trace",
                "application crash",
                "runtime failure",
                "failed to render",
                "rendering error",
                "http 500",
            )
        )
    )
    if application_exception_condition:
        selected.append("RB-003")

    compute_network_condition = (
        any(term in text for term in ("compute cluster", "application compute"))
        and any(
            term in text
            for term in (
                "network partition",
                "cannot establish internal connections",
                "compute-connection stage",
                "compute cluster unavailable",
                "compute cluster failure",
                "node unavailable",
                "host unavailable",
            )
        )
    )
    if compute_network_condition:
        selected.append("RB-004")

    # Select specific technical runbooks before generic symptom runbooks.
    generic_ids = {"RB-001", "RB-002", "RB-012"}
    for runbook_id, keywords in RUNBOOK_KEYWORDS:
        if runbook_id in generic_ids:
            continue
        if any(keyword in text for keyword in keywords):
            selected.append(runbook_id)

    specific_selected = any(
        runbook_id not in {"RB-001", "RB-002", "RB-012"}
        for runbook_id in selected
    )
    unavailable = (
        incident.service_impact.availability_state.value == "unavailable"
    )
    service_remains_available = (
        incident.service_impact.availability_state.value
        in {"available", "partially_degraded"}
    )
    performance_signal = any(
        keyword in text
        for keyword in (
            "latency",
            "slow",
            "degraded",
            "degradation",
            "throughput",
            "queue backlog",
            "queue depth",
        )
    )

    # Unexplained loss of an essential service function must use the bounded
    # availability runbook rather than a performance runbook activated by a
    # generic timeout symptom.
    if unavailable and not specific_selected:
        insert_at = 1 if selected and selected[0] == "RB-012" else 0
        selected.insert(insert_at, "RB-001")
    elif service_remains_available and performance_signal and not specific_selected:
        # Use the generic performance runbook only when no more specific
        # technical performance runbook has already been selected.
        selected.append("RB-002")

    return tuple(dict.fromkeys(selected[:3]))


def select_operational_knowledge(
    incident: IncidentInput,
    knowledge: KnowledgeBundle,
) -> SelectedKnowledge:
    docs = knowledge.documents
    reported_ids = {item.value for item in incident.reported_affected_service_ids}
    relevant_ids = set(reported_ids)

    relevant_dependencies = []
    for dependency in docs["dependencies.json"]["dependencies"]:
        if dependency["dependent"] in reported_ids:
            relevant_dependencies.append(dependency)
            relevant_ids.add(dependency["dependency"])

    relevant_services = [
        item for item in docs["services.json"]["services"]
        if item["id"] in relevant_ids
    ]
    relevant_ownership = [
        item for item in docs["ownership_map.json"]["ownership"]
        if item["component_id"] in relevant_ids
    ]

    relevant_group_ids: set[str] = set()
    for item in relevant_services:
        relevant_group_ids.add(item["primary_resolver_group"])
    for item in relevant_ownership:
        relevant_group_ids.add(item["primary_group"])
        relevant_group_ids.update(item.get("secondary_groups", []))

    relevant_groups = [
        item for item in docs["resolver_groups.json"]["resolver_groups"]
        if item["id"] in relevant_group_ids or item["id"] == "RG-OPS"
    ]

    selected_runbook_ids = _select_runbook_ids(incident)
    selected_runbooks = [
        item for item in docs["runbooks.json"]["runbooks"]
        if item["id"] in selected_runbook_ids
    ]

    selected_action_ids: set[str] = set()
    for runbook in selected_runbooks:
        selected_action_ids.update(runbook.get("recommended_action_ids", []))
        selected_action_ids.update(runbook.get("conditional_action_ids", []))

    # Cross-cutting actions must be present in the selected knowledge even when
    # they are not native actions of the primary technical runbook. Otherwise
    # the guardrail layer can correctly add the action but the validator will
    # reject its KB reference as unavailable.
    direct_application_failure = _has_direct_application_failure_evidence(incident)

    if incident.reported_unknowns and "RB-010" in selected_runbook_ids:
        selected_action_ids.add("ACT-009")

    if direct_application_failure and incident.reported_unknowns:
        selected_action_ids.add("ACT-009")

    if (
        direct_application_failure
        and incident.service_impact.impact_scope
        in {ImpactScope.SERVICE_WIDE, ImpactScope.WIDESPREAD}
    ):
        selected_action_ids.add("ACT-001")

    selected_actions = [
        item for item in docs["runbooks.json"]["common_actions"]
        if item["id"] in selected_action_ids
    ]

    payload = {
        "severity_matrix": docs["severity_matrix.json"],
        "incident_categories": docs["incident_categories.json"],
        "relevant_services": relevant_services,
        "relevant_dependencies": relevant_dependencies,
        "relevant_ownership": relevant_ownership,
        "relevant_resolver_groups": relevant_groups,
        "selected_runbooks": selected_runbooks,
        "selected_common_actions": selected_actions,
        "global_runbook_rules": docs["runbooks.json"]["global_rules"],
        "globally_prohibited_actions": docs["runbooks.json"]["globally_prohibited_actions"],
    }

    refs: set[str] = set()
    for level in docs["severity_matrix.json"]["severity_levels"]:
        refs.add(f"KB:SEVERITY:{level['name']}")
    for category in docs["incident_categories.json"]["categories"]:
        refs.add(f"KB:{category['code']}")
    for item in relevant_services:
        refs.add(f"KB:{item['id']}")
    for item in relevant_dependencies:
        refs.add(f"KB:DEP:{item['dependent']}:{item['dependency']}")
    for item in relevant_groups:
        refs.add(f"KB:{item['id']}")
    for item in selected_runbooks:
        refs.add(f"KB:{item['id']}")
    for item in selected_actions:
        refs.add(f"KB:{item['id']}")

    return SelectedKnowledge(
        payload=payload,
        allowed_refs=frozenset(refs),
        selected_runbook_ids=selected_runbook_ids,
    )
