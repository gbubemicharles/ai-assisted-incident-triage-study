from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any

from context_builder import SelectedKnowledge
from knowledge_loader import KnowledgeBundle
from schemas import (
    AvailabilityState,
    CategoryAssessment,
    DecisionField,
    ImpactScope,
    IncidentCategoryCode,
    IncidentInput,
    InformationGap,
    ResolverGroupID,
    RoutingRecommendation,
    ServiceComponentID,
    SeverityAssessment,
    SeverityLevel,
    TriageOutput,
    WorkaroundStatus,
)


@dataclass(frozen=True)
class GuardrailChange:
    field: str
    original: Any
    revised: Any
    reason: str
    rule_id: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "original": _json_value(self.original),
            "revised": _json_value(self.revised),
            "reason": self.reason,
            "rule_id": self.rule_id,
        }


def _json_value(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "value"):
        return value.value
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    return value


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def _incident_text(incident: IncidentInput) -> str:
    parts = [
        incident.title,
        incident.alert_or_symptom,
        incident.service_impact.user_impact_description,
        *incident.environmental_context,
        *incident.reported_unknowns,
        *incident.additional_context,
    ]
    parts.extend(item.observation for item in incident.technical_evidence)
    parts.extend(change.description for change in incident.recent_changes)
    return _normalise(" ".join(parts))


def _evidence_refs(incident: IncidentInput, limit: int = 3) -> list[str]:
    return [item.evidence_id for item in incident.technical_evidence[:limit]]


def _summary_evidence_refs(
    incident: IncidentInput,
    summary: str,
    limit: int = 3,
) -> list[str]:
    """Select the evidence items whose wording most directly supports the summary."""
    summary_words = set(re.findall(r"[a-zA-Z0-9]{4,}", summary.lower()))
    scored: list[tuple[int, int, str]] = []
    for index, item in enumerate(incident.technical_evidence):
        evidence_text = f"{item.source_name} {item.observation}".lower()
        evidence_words = set(re.findall(r"[a-zA-Z0-9]{4,}", evidence_text))
        overlap = len(summary_words & evidence_words)
        scored.append((overlap, -index, item.evidence_id))

    ranked = [
        evidence_id
        for _, _, evidence_id in sorted(scored, reverse=True)
    ]
    return ranked[:limit]


def _enrich_summary(
    incident: IncidentInput,
    summary: str,
    severity: SeverityLevel,
) -> str:
    """Preserve the model summary while adding material structured impact context."""
    revised = _soften(summary).strip()

    if _has_direct_message_backlog_evidence(incident):
        function = incident.service_impact.business_function_affected.strip()
        function = function[0].upper() + function[1:] if function else "Notifications"
        completion_note = "messages generally continue to complete"
        no_loss_text = " ".join(incident.additional_context).lower()
        if "no messages are confirmed lost or duplicated" in no_loss_text:
            completion_note += " and none are confirmed lost or duplicated"
        revised = (
            f"{function} remain available but are delayed, associated with a "
            f"Message Broker queue backlog; {completion_note}."
        )

    if _has_direct_application_failure_evidence(incident):
        evidence_text = " ".join(
            item.observation for item in incident.technical_evidence
        ).lower()
        dependency_boundary = any(
            term in evidence_text
            for term in (
                "before calls are made",
                "before any dependency call",
                "before dependency calls",
                "do not reach those dependencies",
                "does not reach those dependencies",
            )
        )
        if dependency_boundary and "before" not in revised.lower():
            revised = revised.rstrip(".") + (
                ". Supplied traces show that the failed requests stop before the "
                "named downstream dependency calls."
            )

    if (
        _has_direct_application_failure_evidence(incident)
        and severity in {SeverityLevel.HIGH, SeverityLevel.CRITICAL}
        and incident.service_impact.impact_scope
        in {ImpactScope.SERVICE_WIDE, ImpactScope.WIDESPREAD}
    ):
        impact_description = (
            incident.service_impact.user_impact_description or ""
        ).strip()
        percentage_match = re.search(
            r"\b\d+(?:\.\d+)?\s+percent\b",
            impact_description,
            flags=re.IGNORECASE,
        )
        magnitude_present = any(
            term in revised.lower()
            for term in (
                "large proportion",
                "most ",
                "majority",
                "service-wide",
                "widespread",
            )
        )
        if percentage_match:
            magnitude_present = (
                percentage_match.group(0).lower() in revised.lower()
            )
        if impact_description and not magnitude_present:
            impact_clause = impact_description.split(",", 1)[0].rstrip(".")
            revised = revised.rstrip(".") + f". {impact_clause}."

    geographic_scope = incident.service_impact.geographic_scope
    if (
        geographic_scope
        and severity in {SeverityLevel.HIGH, SeverityLevel.CRITICAL}
        and geographic_scope.lower() not in revised.lower()
    ):
        revised = revised.rstrip(".") + (
            f". The reported impact covers {geographic_scope}."
        )
    return revised


def _service_index(knowledge: KnowledgeBundle) -> dict[str, dict[str, Any]]:
    return {
        item["id"]: item
        for item in knowledge.documents["services.json"]["services"]
    }


def _ownership_index(knowledge: KnowledgeBundle) -> dict[str, str]:
    return {
        item["component_id"]: item["primary_group"]
        for item in knowledge.documents["ownership_map.json"]["ownership"]
    }


def _dependencies_for_reported(
    incident: IncidentInput,
    knowledge: KnowledgeBundle,
) -> list[dict[str, Any]]:
    reported = {item.value for item in incident.reported_affected_service_ids}
    return [
        item
        for item in knowledge.documents["dependencies.json"]["dependencies"]
        if item["dependent"] in reported
    ]


def _component_aliases(knowledge: KnowledgeBundle) -> dict[str, tuple[str, ...]]:
    aliases: dict[str, tuple[str, ...]] = {}
    for item in knowledge.documents["services.json"]["services"]:
        name = item["name"].lower()
        values = {item["id"].lower(), name}
        values.add(name.replace(" and ", " "))
        values.add(name.replace(" platform", ""))
        values.add(name.replace(" service", ""))
        values.add(name.replace(" cluster", ""))
        if item["id"] == "EXT-PAYMENT":
            values.update({"external payment gateway", "payment gateway"})
        elif item["id"] == "EXT-COMMS":
            values.update({"email provider", "sms provider", "communications provider"})
        elif item["id"] == "PLT-DATABASE":
            values.update({"transaction database", "database"})
        elif item["id"] == "PLT-COMPUTE":
            values.update({"compute cluster", "application compute"})
        elif item["id"] == "PLT-MESSAGING":
            values.update({"message broker", "broker"})
        elif item["id"] == "PLT-EDGE":
            values.update({"dns", "cdn", "load balancer", "load-balancing"})
        elif item["id"] == "PLT-STORAGE":
            values.update({"object storage", "storage platform"})
        aliases[item["id"]] = tuple(sorted(values, key=len, reverse=True))
    return aliases


HEALTHY_TERMS = (
    "healthy",
    "operating normally",
    "operational",
    "available",
    "no issue",
    "no issues",
    "not affected",
)

FAILURE_TERMS = (
    "unavailable",
    "failure",
    "failing",
    "failed",
    "error",
    "errors",
    "http 500",
    "http 502",
    "http 503",
    "timeout",
    "timeouts",
    "expired",
    "invalid",
    "missing",
    "refused",
    "degraded",
    "latency",
    "packet loss",
    "network partition",
    "cannot establish internal connections",
    "compute-connection stage",
    "unreachable",
    "down",
    "queue backlog",
    "queue depth",
    "queued message age",
    "consumer delay",
    "waiting in the message broker queue",
)


def _component_states(
    incident: IncidentInput,
    knowledge: KnowledgeBundle,
) -> tuple[set[str], set[str]]:
    aliases = _component_aliases(knowledge)
    healthy: set[str] = set()
    implicated: set[str] = set()

    statements = [item.observation for item in incident.technical_evidence]
    statements.extend(incident.environmental_context)
    statements.extend(incident.additional_context)

    for statement in statements:
        text = _normalise(statement)
        for component_id, names in aliases.items():
            if not any(name in text for name in names):
                continue
            has_healthy = any(term in text for term in HEALTHY_TERMS)
            has_failure = any(term in text for term in FAILURE_TERMS)
            if has_healthy and not has_failure:
                healthy.add(component_id)
            if has_failure:
                implicated.add(component_id)

    implicated.difference_update(healthy)
    return healthy, implicated


def _has_direct_message_backlog_evidence(incident: IncidentInput) -> bool:
    """Return True when broker queueing is directly evidenced, not merely named."""
    evidence_text = " ".join(
        f"{item.source_name} {item.observation}"
        for item in incident.technical_evidence
    ).lower()
    broker_named = any(
        term in evidence_text
        for term in ("message broker", "broker queue", "outbound-notification queue")
    )
    backlog_signal = any(
        term in evidence_text
        for term in (
            "queue backlog",
            "queue depth",
            "queued message age",
            "oldest queued message",
            "waiting in the message broker queue",
            "consumer delay",
        )
    )
    service_available = incident.service_impact.availability_state in {
        AvailabilityState.AVAILABLE,
        AvailabilityState.PARTIALLY_DEGRADED,
    }
    return broker_named and backlog_signal and service_available


def _has_direct_application_failure_evidence(incident: IncidentInput) -> bool:
    """Return True when technical evidence directly identifies an application failure."""
    evidence_text = " ".join(
        f"{item.source_name} {item.observation}"
        for item in incident.technical_evidence
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
                "application-level http 500",
            )
        )
    )


def _highest_reported_criticality(
    incident: IncidentInput,
    knowledge: KnowledgeBundle,
) -> str:
    ranking = {"Standard": 1, "Important": 2, "Critical": 3}
    services = _service_index(knowledge)
    values = [
        services[item.value]["business_criticality"]
        for item in incident.reported_affected_service_ids
        if item.value in services
    ]
    return max(values, key=lambda value: ranking[value], default="Standard")


def _derive_severity(
    incident: IncidentInput,
    knowledge: KnowledgeBundle,
) -> tuple[SeverityLevel, str, bool, list[str]]:
    impact = incident.service_impact
    criticality = _highest_reported_criticality(incident, knowledge)
    reported_ids = [item.value for item in incident.reported_affected_service_ids]
    refs = [f"KB:SEVERITY:High"]
    if reported_ids:
        refs.append(f"KB:{reported_ids[0]}")
    refs.extend(_evidence_refs(incident, 2))

    provisional = (
        impact.workaround_status == WorkaroundStatus.UNKNOWN
        or impact.impact_scope == ImpactScope.UNKNOWN
        or impact.geographic_scope is None
        or bool(incident.reported_unknowns)
    )

    if (
        impact.data_loss_or_corruption_confirmed
        or impact.serious_security_exposure_confirmed
    ):
        level = SeverityLevel.CRITICAL
        reason = (
            "Critical severity is required because serious data loss, corruption or "
            "security exposure is explicitly confirmed."
        )
    elif (
        impact.availability_state in {
            AvailabilityState.UNAVAILABLE,
            AvailabilityState.SEVERELY_DEGRADED,
        }
        and impact.impact_scope in {ImpactScope.WIDESPREAD, ImpactScope.MULTI_SERVICE}
        and criticality == "Critical"
        and impact.workaround_status == WorkaroundStatus.NONE
    ):
        level = SeverityLevel.CRITICAL
        reason = (
            "Critical severity is supported by widespread or multi-service impact to "
            "a business-critical function with no effective workaround."
        )
    elif (
        impact.availability_state == AvailabilityState.UNAVAILABLE
        and criticality == "Critical"
        and impact.workaround_status == WorkaroundStatus.NONE
    ):
        level = SeverityLevel.CRITICAL
        reason = (
            "Critical severity is supported by complete unavailability of a "
            "business-critical function with no effective workaround."
        )
    elif impact.availability_state in {
        AvailabilityState.UNAVAILABLE,
        AvailabilityState.SEVERELY_DEGRADED,
    }:
        level = SeverityLevel.HIGH
        reason = (
            "High severity is supported because major service functionality is "
            "unavailable or severely degraded. The assessment remains provisional "
            "where scope or workaround availability is unconfirmed."
        )
    elif impact.availability_state == AvailabilityState.PARTIALLY_DEGRADED:
        if (
            criticality == "Critical"
            and impact.impact_scope in {ImpactScope.SERVICE_WIDE, ImpactScope.WIDESPREAD}
            and impact.workaround_status in {WorkaroundStatus.NONE, WorkaroundStatus.LIMITED}
        ):
            level = SeverityLevel.HIGH
            reason = (
                "High severity is supported by service-wide degradation of a critical "
                "business function with no reliable workaround."
            )
        else:
            level = SeverityLevel.MEDIUM
            reason = (
                "Medium severity is supported by a contained or partial disruption "
                "with manageable operational impact."
            )
    elif impact.availability_state == AvailabilityState.AVAILABLE:
        if impact.impact_scope == ImpactScope.ISOLATED:
            level = SeverityLevel.LOW
            reason = (
                "Low severity is supported because the service remains available and "
                "the reported impact is isolated."
            )
        else:
            level = SeverityLevel.MEDIUM
            reason = (
                "Medium severity is supported because the service remains available "
                "but a non-trivial operational impact is reported."
            )
    else:
        level = SeverityLevel.MEDIUM
        reason = (
            "Medium provisional severity is assigned because the available impact "
            "evidence is insufficient for a higher or lower classification."
        )

    refs[0] = f"KB:SEVERITY:{level.value}"
    return level, reason, provisional, list(dict.fromkeys(refs))[:5]


DEPENDENCY_CONFIG_TERMS = (
    "external payment gateway",
    "third-party dependency",
    "external dependency",
    "dependency failure",
    "dependency unavailable",
    "expired certificate",
    "certificate expired",
    "expired token",
    "token expired",
    "invalid credential",
    "invalid credentials",
    "missing credential",
    "incorrect endpoint",
    "configuration error",
    "configuration mismatch",
    "missing environment variable",
    "missing secret",
)


APPLICATION_TERMS = (
    "unhandled exception",
    "exception",
    "stack trace",
    "null reference",
    "crash loop",
    "application crash",
    "application-level http 500",
    "business logic",
    "runtime failure",
    "failed to render",
    "rendering error",
)

INFRA_NETWORK_TERMS = (
    "dns resolution failure",
    "dns failure",
    "firewall denial",
    "firewall blocked",
    "route table error",
    "routing failure",
    "packet loss",
    "network partition",
    "load balancer failure",
    "load balancer error",
    "node unavailable",
    "host unavailable",
    "storage failure",
    "compute cluster unavailable",
    "compute cluster failure",
)

PERFORMANCE_TERMS = (
    "latency",
    "throughput",
    "queue backlog",
    "queue depth",
    "slow",
    "degraded",
    "intermittent timeout",
)


def _derive_category(
    incident: IncidentInput,
    knowledge: KnowledgeBundle,
    implicated: set[str],
) -> tuple[IncidentCategoryCode, str, list[str]]:
    text = _incident_text(incident)
    dependencies = _dependencies_for_reported(incident, knowledge)
    dependency_ids = {item["dependency"] for item in dependencies}
    implicated_dependencies = implicated & dependency_ids

    external_dependency_failure = any(
        item.startswith("EXT-") for item in implicated_dependencies
    )
    direct_dependency_language = any(
        term in text for term in DEPENDENCY_CONFIG_TERMS
    )
    credential_language = any(
        term in text
        for term in (
            "expired credential",
            "invalid credential",
            "missing credential",
            "expired token",
            "token expired",
            "invalid token",
            "missing token",
            "expired certificate",
            "certificate expired",
            "invalid certificate",
            "incorrect endpoint",
            "configuration error",
            "configuration mismatch",
            "missing environment variable",
            "missing secret",
        )
    )
    explicit_infra_network_failure = (
        any(term in text for term in INFRA_NETWORK_TERMS)
        and any(item.startswith("PLT-") for item in implicated)
    )
    performance_evidence = any(term in text for term in PERFORMANCE_TERMS)
    service_remains_available = (
        incident.service_impact.availability_state
        in {AvailabilityState.AVAILABLE, AvailabilityState.PARTIALLY_DEGRADED}
    )

    if explicit_infra_network_failure:
        code = IncidentCategoryCode.INFRA_NETWORK
        reason = (
            "Infrastructure or Network Failure is selected because the evidence "
            "directly identifies a platform or connectivity failure condition."
        )
    elif implicated_dependencies and (
        external_dependency_failure or direct_dependency_language
    ):
        code = IncidentCategoryCode.DEPENDENCY_CONFIG
        reason = (
            "Dependency or Configuration Failure is selected because the supplied "
            "evidence directly implicates a required service dependency."
        )
    elif credential_language:
        code = IncidentCategoryCode.DEPENDENCY_CONFIG
        reason = (
            "Dependency or Configuration Failure is selected because the evidence "
            "identifies an invalid, missing, expired or incompatible configuration item."
        )
    elif any(term in text for term in APPLICATION_TERMS):
        code = IncidentCategoryCode.APPLICATION
        reason = (
            "Application Failure is selected because the evidence directly identifies "
            "application code, runtime or processing failure."
        )
    elif service_remains_available and performance_evidence:
        code = IncidentCategoryCode.PERFORMANCE
        reason = (
            "Performance Degradation is selected because the service remains available "
            "while latency, throughput, error rate or processing performance is impaired."
        )
    elif incident.service_impact.availability_state == AvailabilityState.UNAVAILABLE:
        code = IncidentCategoryCode.AVAILABILITY
        reason = (
            "Service Unavailability is selected because essential functionality is "
            "unavailable and no more specific technical category is directly supported."
        )
    else:
        code = IncidentCategoryCode.PERFORMANCE
        reason = (
            "Performance Degradation is selected provisionally because service impact "
            "is present without sufficient evidence for a more specific technical category."
        )

    refs = [f"KB:{code.value}"] + _evidence_refs(incident, 3)
    return code, reason, list(dict.fromkeys(refs))[:5]

def _choose_primary_area(
    incident: IncidentInput,
    category: IncidentCategoryCode,
    knowledge: KnowledgeBundle,
    healthy: set[str],
    implicated: set[str],
) -> tuple[ServiceComponentID, list[ServiceComponentID], str, list[str]]:
    dependencies = _dependencies_for_reported(incident, knowledge)
    dependency_ids = [item["dependency"] for item in dependencies]
    reported_ids = [item.value for item in incident.reported_affected_service_ids]

    candidates = [item for item in dependency_ids if item in implicated and item not in healthy]
    candidate_counts = Counter(candidates)
    unique_candidates = list(dict.fromkeys(candidates))

    if category == IncidentCategoryCode.DEPENDENCY_CONFIG and unique_candidates:
        external = [item for item in unique_candidates if item.startswith("EXT-")]
        ranked = sorted(
            external or unique_candidates,
            key=lambda item: (-candidate_counts[item], unique_candidates.index(item)),
        )
        primary_id = ranked[0]
    elif category in {
        IncidentCategoryCode.INFRA_NETWORK,
        IncidentCategoryCode.PERFORMANCE,
    } and unique_candidates:
        platform = [item for item in unique_candidates if item.startswith("PLT-")]
        ranked = sorted(
            platform or unique_candidates,
            key=lambda item: (-candidate_counts[item], unique_candidates.index(item)),
        )
        primary_id = ranked[0]
    else:
        non_healthy_reported = [item for item in reported_ids if item not in healthy]
        primary_id = (non_healthy_reported or reported_ids)[0]

    # When an implicated dependency is selected as primary, retain the reported
    # service as the visible affected service even when its application
    # instances are healthy. Component health and service-level impact are not
    # equivalent concepts.
    additional_ids = [
        item for item in reported_ids
        if item != primary_id
    ]

    if primary_id in dependency_ids:
        reason = (
            "The selected primary area is the directly implicated dependency, while "
            "the reported service remains the visible affected service."
        )
        dep_ref = next(
            (
                f"KB:DEP:{item['dependent']}:{item['dependency']}"
                for item in dependencies
                if item["dependency"] == primary_id
            ),
            None,
        )
    else:
        reason = (
            "The selected primary area is the reported service most directly supported "
            "as affected by the available evidence."
        )
        dep_ref = None

    refs = [ref for ref in [dep_ref, f"KB:{primary_id}"] if ref]
    refs.extend(_evidence_refs(incident, 3))

    return (
        ServiceComponentID(primary_id),
        [ServiceComponentID(item) for item in additional_ids],
        reason,
        list(dict.fromkeys(refs))[:5],
    )


def _derive_routing(
    incident: IncidentInput,
    severity: SeverityLevel,
    primary_area: ServiceComponentID,
    knowledge: KnowledgeBundle,
) -> tuple[ResolverGroupID, list[ResolverGroupID], str, list[str], bool]:
    ownership = _ownership_index(knowledge)
    primary_group_value = ownership.get(primary_area.value, "RG-OPS")
    primary_group = ResolverGroupID(primary_group_value)

    multi_service = (
        incident.service_impact.impact_scope == ImpactScope.MULTI_SERVICE
        or len(incident.reported_affected_service_ids) > 1
    )
    unclear = primary_group == ResolverGroupID.RG_OPS
    coordination: list[ResolverGroupID] = []
    if primary_group != ResolverGroupID.RG_OPS and (
        severity == SeverityLevel.CRITICAL or multi_service
    ):
        coordination.append(ResolverGroupID.RG_OPS)

    if unclear:
        reason = (
            "Cloud Operations Coordination is selected provisionally because the "
            "technical owner cannot be determined from the available evidence."
        )
    else:
        reason = (
            "The resolver group is selected from the ownership record for the directly "
            "implicated technical area."
        )

    refs = [f"KB:{primary_group.value}", f"KB:{primary_area.value}"]
    return primary_group, coordination, reason, refs, unclear


CAUSAL_REPLACEMENTS = (
    (re.compile(r"\bis unavailable due to\b", re.IGNORECASE), "is unavailable and is associated with"),
    (re.compile(r"\bare unavailable due to\b", re.IGNORECASE), "are unavailable and are associated with"),
    (re.compile(r"\bdue to\b", re.IGNORECASE), "associated with"),
    (re.compile(r"\bcaused by\b", re.IGNORECASE), "associated with"),
    (re.compile(r"\bis caused by\b", re.IGNORECASE), "is associated with"),
    (re.compile(r"\bdirect cause\b", re.IGNORECASE), "directly implicated area"),
    (re.compile(r"\bprimary cause\b", re.IGNORECASE), "primary implicated area"),
    (re.compile(r"\bconfirmed cause\b", re.IGNORECASE), "confirmed association"),
    (re.compile(r"\bdefinitive cause\b", re.IGNORECASE), "definitive explanation"),
    (re.compile(r"\broot cause timeline\b", re.IGNORECASE), "incident timeline"),
    (re.compile(r"\broot cause\b", re.IGNORECASE), "underlying cause"),
)


def _soften(text: str) -> str:
    result = text
    for pattern, replacement in CAUSAL_REPLACEMENTS:
        result = pattern.sub(replacement, result)
    return result


PROHIBITED_ACTION_PATTERNS = (
    re.compile(r"\brestart\b", re.IGNORECASE),
    re.compile(r"\breboot\b", re.IGNORECASE),
    re.compile(r"\brotate\b.*\bcredential", re.IGNORECASE),
    re.compile(r"\brenew\b.*\bcertificate", re.IGNORECASE),
    re.compile(r"\bdisable\b.*\bauthentication", re.IGNORECASE),
    re.compile(r"\bbypass\b.*\b(access|security)", re.IGNORECASE),
    re.compile(r"\bpurge\b.*\b(queue|message)", re.IGNORECASE),
    re.compile(r"\bdelete\b.*\b(queue|message)", re.IGNORECASE),
    re.compile(r"\bscale\b.*\b(resource|cluster|node|service)", re.IGNORECASE),
    re.compile(r"\broll\s*back\b", re.IGNORECASE),
    re.compile(r"\bredeploy\b", re.IGNORECASE),
    re.compile(r"\bcontact\b.*\b(provider|vendor)", re.IGNORECASE),
)


def _action_catalog(knowledge: KnowledgeBundle) -> dict[str, str]:
    return {
        item["id"]: item["action"]
        for item in knowledge.documents["runbooks.json"]["common_actions"]
    }


ACTION_RATIONALES = {
    "ACT-001": "Confirm the scale and scope of the reported impact before finalising severity and coordination requirements.",
    "ACT-002": "Establish the incident timeline and correlate the supplied operational evidence.",
    "ACT-003": "Review relevant telemetry to verify the observed failure pattern and gather evidence for further investigation.",
    "ACT-004": "Check whether recent changes coincide with the incident without treating correlation as confirmed causation.",
    "ACT-005": "Verify the health of the directly relevant dependencies and distinguish local symptoms from dependency failure.",
    "ACT-006": "Confirm technical ownership and ensure the incident is routed to the responsible resolver group.",
    "ACT-007": "Determine whether a documented and approved workaround is available for response planning.",
    "ACT-008": "Coordinate the response where the confirmed impact is Critical or spans multiple services.",
    "ACT-009": "Obtain the missing evidence required to refine the provisional triage assessment.",
    "ACT-010": "Preserve the current incident evidence and triage record for handover and subsequent investigation.",
}


def _best_action_id(action_text: str, candidate_ids: list[str], catalog: dict[str, str]) -> str | None:
    if not candidate_ids:
        return None
    scored = [
        (
            SequenceMatcher(None, _normalise(action_text), _normalise(catalog.get(item, ""))).ratio(),
            item,
        )
        for item in candidate_ids
    ]
    score, item = max(scored, default=(0.0, None))
    return item if item is not None and score >= 0.25 else candidate_ids[0]


def _normalise_actions(
    incident: IncidentInput,
    output: TriageOutput,
    selected: SelectedKnowledge,
    knowledge: KnowledgeBundle,
    routing_provisional: bool,
) -> tuple[list[Any], list[GuardrailChange]]:
    catalog = _action_catalog(knowledge)
    selected_action_ids = sorted(
        ref.removeprefix("KB:")
        for ref in selected.allowed_refs
        if re.fullmatch(r"KB:ACT-[0-9]{3}", ref)
    )
    selected_runbooks = list(selected.selected_runbook_ids)
    primary_runbook_id = selected_runbooks[0] if selected_runbooks else None

    runbook_index = {
        item["id"]: item
        for item in knowledge.documents["runbooks.json"]["runbooks"]
    }
    primary_runbook = (
        runbook_index.get(primary_runbook_id)
        if primary_runbook_id is not None
        else None
    )
    recommended_ids = set(
        primary_runbook.get("recommended_action_ids", [])
        if primary_runbook is not None
        else selected_action_ids
    )
    conditional_ids = set(
        primary_runbook.get("conditional_action_ids", [])
        if primary_runbook is not None
        else []
    )
    cross_cutting_ids: set[str] = set()
    if incident.reported_unknowns and primary_runbook_id == "RB-010":
        cross_cutting_ids.add("ACT-009")
    if (
        incident.reported_unknowns
        and output.incident_category.code == IncidentCategoryCode.APPLICATION
        and "ACT-009" not in recommended_ids
        and "ACT-009" not in conditional_ids
    ):
        cross_cutting_ids.add("ACT-009")
    if (
        output.incident_category.code == IncidentCategoryCode.APPLICATION
        and output.severity.level == SeverityLevel.HIGH
        and incident.service_impact.impact_scope
        in {ImpactScope.SERVICE_WIDE, ImpactScope.WIDESPREAD}
        and "ACT-001" not in recommended_ids
        and "ACT-001" not in conditional_ids
    ):
        cross_cutting_ids.add("ACT-001")
    permitted_ids = recommended_ids | conditional_ids | cross_cutting_ids

    healthy_components, _ = _component_states(incident, knowledge)
    dependency_ids = {
        item["dependency"]
        for item in _dependencies_for_reported(incident, knowledge)
    }
    all_relevant_dependencies_healthy = bool(dependency_ids) and dependency_ids.issubset(
        healthy_components
    )

    revised_by_id: dict[str, Any] = {}
    changes: list[GuardrailChange] = []

    for index, action in enumerate(output.initial_actions):
        if any(pattern.search(action.action) for pattern in PROHIBITED_ACTION_PATTERNS):
            changes.append(
                GuardrailChange(
                    field=f"initial_actions[{index}]",
                    original=action,
                    revised=None,
                    reason="Unsafe or out-of-scope operational action was removed.",
                    rule_id="GR-ACTION-001",
                )
            )
            continue

        cited_action_ids = [
            ref.removeprefix("KB:")
            for ref in action.source_refs
            if re.fullmatch(r"KB:ACT-[0-9]{3}", ref)
        ]
        candidates = cited_action_ids or selected_action_ids
        action_id = action.common_action_id or _best_action_id(
            action.action, candidates, catalog
        )
        if action_id is None or action_id not in catalog:
            continue

        if (
            action_id == "ACT-005"
            and all_relevant_dependencies_healthy
            and output.incident_category.code != IncidentCategoryCode.AVAILABILITY
        ):
            changes.append(
                GuardrailChange(
                    field=f"initial_actions[{index}]",
                    original=action,
                    revised=None,
                    reason=(
                        "Dependency-validation action was removed because every relevant "
                        "dependency is explicitly reported healthy."
                    ),
                    rule_id="GR-ACTION-006",
                )
            )
            continue

        if permitted_ids and action_id not in permitted_ids:
            changes.append(
                GuardrailChange(
                    field=f"initial_actions[{index}]",
                    original=action,
                    revised=None,
                    reason=(
                        "Action was removed because it is not recommended or conditional "
                        "in the selected primary runbook."
                    ),
                    rule_id="GR-ACTION-005",
                )
            )
            continue

        if action_id == "ACT-006" and not routing_provisional:
            changes.append(
                GuardrailChange(
                    field=f"initial_actions[{index}]",
                    original=action,
                    revised=None,
                    reason=(
                        "Redundant ownership-confirmation action was removed because "
                        "routing is conclusive."
                    ),
                    rule_id="GR-ACTION-003",
                )
            )
            continue

        runbook_id = (
            None if action_id in cross_cutting_ids
            else (action.runbook_id or primary_runbook_id)
        )
        incident_refs = [
            ref
            for ref in action.source_refs
            if re.fullmatch(r"[EC][1-9][0-9]*", ref)
        ]
        if not incident_refs:
            incident_refs = _evidence_refs(incident, 2)

        refs = incident_refs + [f"KB:{action_id}"]
        if runbook_id is not None:
            refs.append(f"KB:{runbook_id}")
        refs = list(dict.fromkeys(refs))[:5]

        revised = action.model_copy(
            update={
                "action": catalog[action_id],
                "rationale": ACTION_RATIONALES[action_id],
                "source_refs": refs,
                "common_action_id": action_id,
                "runbook_id": runbook_id,
            },
            deep=True,
        )
        revised_by_id[action_id] = revised
        if revised != action:
            changes.append(
                GuardrailChange(
                    field=f"initial_actions[{index}]",
                    original=action,
                    revised=revised,
                    reason=(
                        "Action text, rationale and traceability were normalised to "
                        "approved runbook guidance."
                    ),
                    rule_id="GR-ACTION-002",
                )
            )

    required_ids: list[str] = []
    unknown_text = " ".join(incident.reported_unknowns).lower()

    # Core evidence-gathering actions from the selected primary runbook.
    for action_id in ("ACT-002", "ACT-003"):
        if action_id in recommended_ids:
            required_ids.append(action_id)

    if incident.recent_changes and "ACT-004" in recommended_ids:
        required_ids.append("ACT-004")

    if (
        output.incident_category.code == IncidentCategoryCode.APPLICATION
        and output.severity.level == SeverityLevel.HIGH
        and incident.service_impact.impact_scope
        in {ImpactScope.SERVICE_WIDE, ImpactScope.WIDESPREAD}
        and ("ACT-001" in recommended_ids or "ACT-001" in cross_cutting_ids)
    ):
        required_ids.append("ACT-001")

    if incident.reported_unknowns and (
        "ACT-009" in recommended_ids or "ACT-009" in cross_cutting_ids
    ):
        required_ids.append("ACT-009")

    if (
        output.severity.level == SeverityLevel.LOW
        and incident.service_impact.impact_scope == ImpactScope.ISOLATED
        and "ACT-010" in recommended_ids
    ):
        required_ids.append("ACT-010")

    if (
        any(
            term in unknown_text
            for term in ("geographical", "geographic", "scope", "affected users")
        )
        and "ACT-001" in recommended_ids
    ):
        required_ids.append("ACT-001")

    if "workaround" in unknown_text and "ACT-007" in recommended_ids:
        required_ids.append("ACT-007")

    if (
        output.affected_area.primary_area_id.value
        not in {item.value for item in incident.reported_affected_service_ids}
        and "ACT-005" in recommended_ids
    ):
        required_ids.append("ACT-005")

    if routing_provisional and "ACT-006" in recommended_ids:
        required_ids.append("ACT-006")

    multi_service = (
        incident.service_impact.impact_scope == ImpactScope.MULTI_SERVICE
        or len(incident.reported_affected_service_ids) > 1
    )
    if (
        (output.severity.level == SeverityLevel.CRITICAL or multi_service)
        and "ACT-008" in recommended_ids
    ):
        required_ids.append("ACT-008")

    if (
        (output.severity.level == SeverityLevel.CRITICAL or multi_service)
        and "ACT-001" in recommended_ids
    ):
        required_ids.append("ACT-001")

    required_ids = list(dict.fromkeys(required_ids))

    template = output.initial_actions[0] if output.initial_actions else None
    for action_id in required_ids:
        if action_id in revised_by_id or action_id not in catalog or template is None:
            continue
        refs = _evidence_refs(incident, 2)
        if action_id == "ACT-004" and incident.recent_changes:
            refs = [incident.recent_changes[0].change_id]
        refs.append(f"KB:{action_id}")
        action_runbook_id = (
            None if action_id in cross_cutting_ids else primary_runbook_id
        )
        if action_runbook_id is not None:
            refs.append(f"KB:{action_runbook_id}")
        added = template.model_copy(
            update={
                "action": catalog[action_id],
                "rationale": ACTION_RATIONALES[action_id],
                "source_refs": list(dict.fromkeys(refs))[:5],
                "common_action_id": action_id,
                "runbook_id": action_runbook_id,
            },
            deep=True,
        )
        revised_by_id[action_id] = added
        changes.append(
            GuardrailChange(
                field="initial_actions",
                original=None,
                revised=added,
                reason=(
                    "A safe action recommended by the selected primary runbook was "
                    "added to address the incident evidence or a reported information gap."
                ),
                rule_id="GR-ACTION-004",
            )
        )

    priority = [
        "ACT-001",
        "ACT-002",
        "ACT-003",
        "ACT-009",
        "ACT-005",
        "ACT-004",
        "ACT-010",
        "ACT-007",
        "ACT-008",
        "ACT-006",
    ]
    ordered = [revised_by_id[item] for item in priority if item in revised_by_id]
    return ordered[:5], changes

def _gap_matches_unknown(gap_text: str, unknown: str) -> bool:
    gap_words = set(re.findall(r"[a-zA-Z]{4,}", gap_text.lower()))
    unknown_words = set(re.findall(r"[a-zA-Z]{4,}", unknown.lower()))
    return bool(gap_words & unknown_words)


def _ensure_information_gaps(
    incident: IncidentInput,
    output: TriageOutput,
) -> tuple[list[InformationGap], list[GuardrailChange]]:
    changes: list[GuardrailChange] = []
    explicit_unknowns = list(incident.reported_unknowns)

    structured_signals: list[tuple[tuple[str, ...], list[DecisionField]]] = []
    if incident.service_impact.geographic_scope is None:
        structured_signals.append(
            (("geographic", "geographical", "region", "location"), [DecisionField.SEVERITY])
        )
    if incident.service_impact.workaround_status == WorkaroundStatus.UNKNOWN:
        structured_signals.append(
            (("workaround",), [DecisionField.SEVERITY, DecisionField.INITIAL_ACTIONS])
        )
    if incident.service_impact.impact_scope == ImpactScope.UNKNOWN:
        structured_signals.append(
            (("impact scope", "affected users", "scope"), [DecisionField.SEVERITY])
        )
    if output.routing.provisional:
        structured_signals.append(
            (("owner", "ownership", "resolver group"), [DecisionField.ROUTING])
        )
    if output.affected_area.provisional:
        structured_signals.append(
            (("affected component", "technical area", "affected service"), [DecisionField.AFFECTED_AREA])
        )

    kept: list[InformationGap] = []
    for gap in output.information_gaps:
        text = gap.missing_information.lower()
        grounded = any(_gap_matches_unknown(text, unknown) for unknown in explicit_unknowns)
        if not grounded:
            grounded = any(
                any(term in text for term in terms)
                for terms, _ in structured_signals
            )

        # Root-cause investigation detail is not automatically a triage information gap.
        root_cause_only = any(
            term in text
            for term in ("root cause", "underlying cause", "exact cause", "nature of the")
        )
        material_provisional_decision = any(
            (decision == DecisionField.SEVERITY and output.severity.provisional)
            or (decision == DecisionField.CATEGORY and output.incident_category.provisional)
            or (decision == DecisionField.AFFECTED_AREA and output.affected_area.provisional)
            or (decision == DecisionField.ROUTING and output.routing.provisional)
            for decision in gap.affected_decisions
        )

        if grounded or (material_provisional_decision and not root_cause_only):
            kept.append(gap)
        else:
            changes.append(
                GuardrailChange(
                    field="information_gaps",
                    original=gap,
                    revised=None,
                    reason=(
                        "An ungrounded or investigation-only gap was removed because it "
                        "does not materially affect the bounded triage decisions."
                    ),
                    rule_id="GR-GAP-002",
                )
            )

    existing = " ".join(item.missing_information.lower() for item in kept)
    for unknown in explicit_unknowns:
        keywords = [word for word in re.findall(r"[a-zA-Z]{4,}", unknown.lower())]
        if keywords and any(word in existing for word in keywords[:3]):
            continue

        lower = unknown.lower()
        affected = [DecisionField.SEVERITY]
        if "workaround" in lower:
            affected.append(DecisionField.INITIAL_ACTIONS)
        if "owner" in lower or "ownership" in lower:
            affected.append(DecisionField.ROUTING)
        if "component" in lower or "service" in lower:
            affected.append(DecisionField.AFFECTED_AREA)

        added = InformationGap(
            missing_information=unknown,
            why_needed="This information is required to refine the provisional triage assessment.",
            affected_decisions=list(dict.fromkeys(affected)),
            requested_evidence=f"Evidence confirming: {unknown}",
        )
        kept.append(added)
        changes.append(
            GuardrailChange(
                field="information_gaps",
                original=None,
                revised=added,
                reason="A reported unknown affecting triage was not represented in the model draft.",
                rule_id="GR-GAP-001",
            )
        )

    return kept[:6], changes


def apply_guardrails(
    incident: IncidentInput,
    model_output: TriageOutput,
    selected: SelectedKnowledge,
    knowledge: KnowledgeBundle,
) -> tuple[TriageOutput, list[GuardrailChange]]:
    """Apply transparent deterministic controls to the LLM's structured draft."""

    changes: list[GuardrailChange] = []
    revised = model_output.model_copy(deep=True)
    healthy, implicated = _component_states(incident, knowledge)

    level, severity_reason, severity_provisional, severity_refs = _derive_severity(
        incident, knowledge
    )
    new_severity = SeverityAssessment(
        level=level,
        rationale=severity_reason,
        source_refs=severity_refs,
        provisional=severity_provisional,
    )
    if revised.severity != new_severity:
        changes.append(
            GuardrailChange(
                field="severity",
                original=revised.severity,
                revised=new_severity,
                reason="Severity was derived from the approved structured impact matrix.",
                rule_id="GR-SEV-001",
            )
        )
        revised.severity = new_severity

    category, category_reason, category_refs = _derive_category(
        incident, knowledge, implicated
    )
    direct_message_backlog = _has_direct_message_backlog_evidence(incident)
    direct_application_failure = _has_direct_application_failure_evidence(incident)
    category_provisional = bool(incident.reported_unknowns) and not (
        (category == IncidentCategoryCode.PERFORMANCE and direct_message_backlog)
        or (
            category == IncidentCategoryCode.APPLICATION
            and direct_application_failure
        )
    )
    new_category = CategoryAssessment(
        code=category,
        rationale=category_reason,
        source_refs=category_refs,
        provisional=category_provisional,
    )
    if revised.incident_category != new_category:
        changes.append(
            GuardrailChange(
                field="incident_category",
                original=revised.incident_category,
                revised=new_category,
                reason="Specific directly evidenced technical categories override symptom categories.",
                rule_id="GR-CAT-001",
            )
        )
        revised.incident_category = new_category

    primary_area, additional_areas, area_reason, area_refs = _choose_primary_area(
        incident, category, knowledge, healthy, implicated
    )
    new_area = revised.affected_area.model_copy(
        update={
            "primary_area_id": primary_area,
            "additional_area_ids": additional_areas,
            "rationale": area_reason,
            "source_refs": area_refs,
            "provisional": bool(incident.reported_unknowns) and not (
                (direct_message_backlog and primary_area.value == "PLT-MESSAGING")
                or (
                    direct_application_failure
                    and category == IncidentCategoryCode.APPLICATION
                    and primary_area.value
                    in {
                        item.value
                        for item in incident.reported_affected_service_ids
                    }
                )
            ),
        },
        deep=True,
    )
    if revised.affected_area != new_area:
        changes.append(
            GuardrailChange(
                field="affected_area",
                original=revised.affected_area,
                revised=new_area,
                reason="Healthy components were excluded and the directly implicated component was prioritised.",
                rule_id="GR-AREA-001",
            )
        )
        revised.affected_area = new_area

    group, coordination, route_reason, route_refs, unclear = _derive_routing(
        incident, level, primary_area, knowledge
    )
    new_routing = RoutingRecommendation(
        primary_resolver_group_id=group,
        coordination_group_ids=coordination,
        rationale=route_reason,
        source_refs=route_refs,
        provisional=unclear,
    )
    if revised.routing != new_routing:
        changes.append(
            GuardrailChange(
                field="routing",
                original=revised.routing,
                revised=new_routing,
                reason="Routing was derived from the ownership map and coordination policy.",
                rule_id="GR-ROUTE-001",
            )
        )
        revised.routing = new_routing

    enriched_summary = _enrich_summary(
        incident,
        revised.incident_summary,
        level,
    )
    if enriched_summary != revised.incident_summary:
        changes.append(
            GuardrailChange(
                field="incident_summary",
                original=revised.incident_summary,
                revised=enriched_summary,
                reason=(
                    "Definitive causal wording was softened and material structured "
                    "impact context was added to the incident summary."
                ),
                rule_id="GR-LANG-001",
            )
        )
        revised.incident_summary = enriched_summary

    summary_refs = _summary_evidence_refs(
        incident,
        revised.incident_summary,
        3,
    ) + [f"KB:{primary_area.value}"]
    summary_refs = list(dict.fromkeys(summary_refs))[:5]
    if revised.summary_source_refs != summary_refs:
        changes.append(
            GuardrailChange(
                field="summary_source_refs",
                original=revised.summary_source_refs,
                revised=summary_refs,
                reason="Summary references were aligned with the supplied evidence and final affected area.",
                rule_id="GR-REF-001",
            )
        )
        revised.summary_source_refs = summary_refs

    actions, action_changes = _normalise_actions(
        incident, revised, selected, knowledge, new_routing.provisional
    )
    changes.extend(action_changes)
    revised.initial_actions = actions

    gaps, gap_changes = _ensure_information_gaps(incident, revised)
    changes.extend(gap_changes)
    revised.information_gaps = gaps

    softened_uncertainty = _soften(revised.uncertainty_statement)
    all_decisions_conclusive = not any(
        (
            revised.severity.provisional,
            revised.incident_category.provisional,
            revised.affected_area.provisional,
            revised.routing.provisional,
        )
    )
    if all_decisions_conclusive and not revised.information_gaps:
        normalised_uncertainty = (
            "The supplied evidence supports the initial triage decisions, but a "
            "definitive root cause has not been established."
        )
    elif (
        direct_message_backlog
        and revised.severity.provisional
        and not revised.incident_category.provisional
        and not revised.affected_area.provisional
        and not revised.routing.provisional
    ):
        normalised_uncertainty = (
            "Severity remains provisional because the backlog duration and underlying "
            "resource condition are not yet known. The category, affected area and "
            "routing decisions are supported by the supplied evidence, but a definitive "
            "root cause has not been established."
        )
    elif (
        revised.severity.provisional
        and not revised.incident_category.provisional
        and not revised.affected_area.provisional
        and not revised.routing.provisional
    ):
        normalised_uncertainty = (
            "Severity remains provisional because material scope or duration information "
            "is unresolved. The category, affected area and routing decisions are "
            "supported by the supplied evidence, but a definitive root cause has not "
            "been established."
        )
    else:
        normalised_uncertainty = softened_uncertainty
    if revised.uncertainty_statement != normalised_uncertainty:
        changes.append(
            GuardrailChange(
                field="uncertainty_statement",
                original=revised.uncertainty_statement,
                revised=normalised_uncertainty,
                reason=(
                    "The uncertainty statement was aligned with the final provisional "
                    "status and bounded root-cause claim."
                ),
                rule_id="GR-LANG-002",
            )
        )
    revised.uncertainty_statement = normalised_uncertainty
    revised.advisory_only = True
    revised.definitive_root_cause_established = False

    return TriageOutput.model_validate(revised.model_dump(mode="json")), changes
