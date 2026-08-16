from __future__ import annotations

import re
from collections.abc import Iterable

from schemas import (
    AvailabilityState,
    ImpactScope,
    IncidentCategoryCode,
    IncidentInput,
    ResolverGroupID,
    SeverityLevel,
    TriageOutput,
)

EXPLICIT_INFRA_NETWORK_PATTERNS = (
    r"\bdns (resolution )?failure\b",
    r"\bfirewall (denial|blocked|failure)\b",
    r"\brouting failure\b",
    r"\broute table (error|failure)\b",
    r"\bpacket loss\b",
    r"\bnetwork partition\b",
    r"\bload balancer (error|failure|unavailable)\b",
    r"\b(node|host) unavailable\b",
    r"\bstorage failure\b",
    r"\bcompute cluster (unavailable|failure)\b",
)

PERFORMANCE_PATTERNS = (
    r"\blatency\b",
    r"\bslow\b",
    r"\bthroughput\b",
    r"\bqueue (backlog|depth)\b",
    r"\bperformance degradation\b",
)


APPLICATION_FAILURE_PATTERNS = (
    r"\b[a-z0-9_]*exception\b",
    r"\bstack trace\b",
    r"\bapplication crash\b",
    r"\bruntime failure\b",
    r"\bfailed to render\b",
    r"\brendering error\b",
)


PROHIBITED_ACTION_PATTERNS = (
    r"\brestart\b",
    r"\breboot\b",
    r"\brotate\b.*\bcredential",
    r"\brenew\b.*\bcertificate",
    r"\bdisable\b.*\bauthentication",
    r"\bbypass\b.*\b(access|security)",
    r"\bpurge\b.*\b(queue|message)",
    r"\bdelete\b.*\b(queue|message)",
    r"\bscale\b.*\b(resource|cluster|node|service)",
    r"\broll\s*back\b",
    r"\bredeploy\b",
    r"\bmodify\b.*\b(configuration|infrastructure|firewall|route|dns)",
    r"\bchange\b.*\b(firewall|route|dns)",
    r"\bcontact\b.*\b(provider|vendor)",
)

PROHIBITED_CAUSAL_PATTERNS = (
    r"\bprimary cause\b",
    r"\bconfirmed cause\b",
    r"\bdefinitive cause\b",
    r"\bdirect cause\b",
    r"\bis caused by\b",
    r"\bcaused by\b",
    r"\bdue to\b",
)


RUNBOOK_CATEGORY_COMPATIBILITY = {
    "RB-001": {IncidentCategoryCode.AVAILABILITY},
    "RB-002": {IncidentCategoryCode.PERFORMANCE},
    "RB-003": {IncidentCategoryCode.APPLICATION},
    "RB-004": {IncidentCategoryCode.INFRA_NETWORK},
    "RB-005": {IncidentCategoryCode.INFRA_NETWORK},
    "RB-006": {
        IncidentCategoryCode.INFRA_NETWORK,
        IncidentCategoryCode.DEPENDENCY_CONFIG,
    },
    "RB-007": {
        IncidentCategoryCode.PERFORMANCE,
        IncidentCategoryCode.INFRA_NETWORK,
    },
    "RB-008": {IncidentCategoryCode.DEPENDENCY_CONFIG},
    "RB-009": {IncidentCategoryCode.DEPENDENCY_CONFIG},
    "RB-010": {
        IncidentCategoryCode.PERFORMANCE,
        IncidentCategoryCode.INFRA_NETWORK,
    },
    "RB-011": {
        IncidentCategoryCode.INFRA_NETWORK,
        IncidentCategoryCode.DEPENDENCY_CONFIG,
    },
    "RB-012": {
        IncidentCategoryCode.AVAILABILITY,
        IncidentCategoryCode.PERFORMANCE,
        IncidentCategoryCode.APPLICATION,
        IncidentCategoryCode.INFRA_NETWORK,
        IncidentCategoryCode.DEPENDENCY_CONFIG,
    },
}

RUNBOOK_RECOMMENDED_ACTIONS = {
    "RB-001": {"ACT-001", "ACT-002", "ACT-003", "ACT-004", "ACT-005", "ACT-006", "ACT-009"},
    "RB-002": {"ACT-001", "ACT-002", "ACT-003", "ACT-004", "ACT-005", "ACT-007", "ACT-009"},
    "RB-003": {"ACT-002", "ACT-003", "ACT-004", "ACT-005", "ACT-006", "ACT-010"},
    "RB-004": {"ACT-001", "ACT-002", "ACT-003", "ACT-004", "ACT-006", "ACT-008"},
    "RB-005": {"ACT-001", "ACT-002", "ACT-003", "ACT-004", "ACT-005", "ACT-006", "ACT-009"},
    "RB-006": {"ACT-001", "ACT-002", "ACT-003", "ACT-004", "ACT-005", "ACT-006", "ACT-009"},
    "RB-007": {"ACT-001", "ACT-002", "ACT-003", "ACT-004", "ACT-006", "ACT-009"},
    "RB-008": {"ACT-001", "ACT-002", "ACT-003", "ACT-005", "ACT-006", "ACT-007", "ACT-008"},
    "RB-009": {"ACT-002", "ACT-003", "ACT-004", "ACT-006", "ACT-009"},
    "RB-010": {"ACT-001", "ACT-002", "ACT-003", "ACT-004", "ACT-005", "ACT-006", "ACT-009"},
    "RB-011": {"ACT-001", "ACT-002", "ACT-003", "ACT-004", "ACT-006", "ACT-009"},
    "RB-012": {"ACT-001", "ACT-002", "ACT-003", "ACT-005", "ACT-008", "ACT-009", "ACT-010"},
}


def _all_source_refs(output: TriageOutput) -> Iterable[str]:
    yield from output.summary_source_refs
    yield from output.severity.source_refs
    yield from output.incident_category.source_refs
    yield from output.affected_area.source_refs
    yield from output.routing.source_refs
    for action in output.initial_actions:
        yield from action.source_refs


def _check_causal_wording(label: str, text: str, errors: list[str]) -> None:
    for pattern in PROHIBITED_CAUSAL_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            errors.append(f"{label} contains prohibited definitive causal wording.")
            break


def _has_explicit_infra_network_evidence(incident_text: str) -> bool:
    return any(
        re.search(pattern, incident_text, flags=re.IGNORECASE)
        for pattern in EXPLICIT_INFRA_NETWORK_PATTERNS
    )


def _has_explicit_application_failure_evidence(incident_text: str) -> bool:
    return any(
        re.search(pattern, incident_text, flags=re.IGNORECASE)
        for pattern in APPLICATION_FAILURE_PATTERNS
    )


def _has_direct_message_backlog_evidence(incident: IncidentInput) -> bool:
    evidence_text = " ".join(
        f"{item.source_name} {item.observation}"
        for item in incident.technical_evidence
    ).lower()
    return (
        any(
            term in evidence_text
            for term in ("message broker", "broker queue", "outbound-notification queue")
        )
        and any(
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
        and incident.service_impact.availability_state
        in {AvailabilityState.AVAILABLE, AvailabilityState.PARTIALLY_DEGRADED}
    )


def validate_triage_output(
    incident: IncidentInput,
    output: TriageOutput,
    allowed_kb_refs: frozenset[str],
) -> list[str]:
    errors: list[str] = []

    if output.incident_id != incident.incident_id:
        errors.append("Output incident_id does not match the submitted incident_id.")

    allowed_refs = set(allowed_kb_refs)
    allowed_refs.update(item.evidence_id for item in incident.technical_evidence)
    allowed_refs.update(change.change_id for change in incident.recent_changes)

    invalid_refs = sorted(set(_all_source_refs(output)) - allowed_refs)
    if invalid_refs:
        errors.append(
            "Output contains unknown or unprovided source references: "
            + ", ".join(invalid_refs)
        )

    _check_causal_wording("Incident summary", output.incident_summary, errors)
    _check_causal_wording("Severity rationale", output.severity.rationale, errors)
    _check_causal_wording("Category rationale", output.incident_category.rationale, errors)
    _check_causal_wording("Affected-area rationale", output.affected_area.rationale, errors)
    for index, action in enumerate(output.initial_actions):
        _check_causal_wording(f"Initial-action rationale {index + 1}", action.rationale, errors)

    if incident.reported_unknowns and not output.information_gaps:
        errors.append(
            "Incident contains reported unknowns but no information-gap entries were returned."
        )

    incident_text = " ".join(
        [
            incident.title,
            incident.alert_or_symptom,
            incident.service_impact.user_impact_description,
            *incident.environmental_context,
            *incident.additional_context,
            *(item.observation for item in incident.technical_evidence),
        ]
    )
    explicit_infra_network = _has_explicit_infra_network_evidence(incident_text)
    explicit_application_failure = _has_explicit_application_failure_evidence(
        incident_text
    )

    if (
        explicit_application_failure
        and not explicit_infra_network
        and incident.service_impact.availability_state
        in {AvailabilityState.AVAILABLE, AvailabilityState.PARTIALLY_DEGRADED}
        and output.incident_category.code != IncidentCategoryCode.APPLICATION
    ):
        errors.append(
            "Explicit application exception or rendering-failure evidence requires "
            "CAT-APPLICATION unless stronger infrastructure evidence is present."
        )

    if (
        explicit_application_failure
        and not explicit_infra_network
        and output.incident_category.code == IncidentCategoryCode.APPLICATION
        and any(
            action.runbook_id not in {None, "RB-003"}
            for action in output.initial_actions
        )
    ):
        errors.append(
            "Application-exception triage actions must be grounded in primary runbook RB-003."
        )

    if (
        explicit_application_failure
        and not explicit_infra_network
        and output.incident_category.code == IncidentCategoryCode.APPLICATION
    ):
        if output.incident_category.provisional:
            errors.append(
                "Direct application-exception evidence supports a non-provisional "
                "CAT-APPLICATION classification."
            )
        if output.affected_area.provisional:
            errors.append(
                "Direct application-exception evidence supports a non-provisional "
                "affected-area decision for the implicated application service."
            )

        reported_ids = {
            item.value for item in incident.reported_affected_service_ids
        }
        if output.affected_area.primary_area_id.value not in reported_ids:
            errors.append(
                "A direct application exception requires the implicated reported "
                "application service as the primary affected area."
            )

        if (
            output.severity.level == SeverityLevel.HIGH
            and incident.service_impact.impact_scope
            in {ImpactScope.SERVICE_WIDE, ImpactScope.WIDESPREAD}
            and not any(
                action.common_action_id == "ACT-001"
                for action in output.initial_actions
            )
        ):
            errors.append(
                "High service-wide application incidents require impact-confirmation "
                "action ACT-001."
            )

        if incident.reported_unknowns and not any(
            action.common_action_id == "ACT-009"
            for action in output.initial_actions
        ):
            errors.append(
                "Application incidents with material reported unknowns require the "
                "cross-cutting evidence-gap action ACT-009."
            )

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
        if dependency_boundary and "before" not in output.incident_summary.lower():
            errors.append(
                "The incident summary must preserve the evidenced boundary that "
                "failed requests stop before downstream dependency calls."
            )

    if (
        output.incident_category.code == IncidentCategoryCode.APPLICATION
        and output.severity.level == SeverityLevel.LOW
        and incident.service_impact.impact_scope == ImpactScope.ISOLATED
        and not any(
            action.common_action_id == "ACT-010"
            for action in output.initial_actions
        )
    ):
        errors.append(
            "Low isolated application incidents require evidence-preservation action ACT-010."
        )

    if (
        output.incident_category.code == IncidentCategoryCode.INFRA_NETWORK
        and incident.service_impact.availability_state
        in {AvailabilityState.AVAILABLE, AvailabilityState.PARTIALLY_DEGRADED}
        and any(
            re.search(pattern, incident_text, flags=re.IGNORECASE)
            for pattern in PERFORMANCE_PATTERNS
        )
        and not explicit_infra_network
    ):
        errors.append(
            "CAT-INFRA-NETWORK requires explicit platform or connectivity failure "
            "evidence; a named platform component with latency alone is insufficient."
        )

    if (
        explicit_infra_network
        and output.incident_category.code != IncidentCategoryCode.INFRA_NETWORK
    ):
        errors.append(
            "Explicit platform or connectivity failure evidence requires "
            "CAT-INFRA-NETWORK unless stronger contradictory evidence is present."
        )

    if (
        re.search(r"\bnetwork partition\b", incident_text, flags=re.IGNORECASE)
        and re.search(r"\b(application )?compute cluster\b", incident_text, flags=re.IGNORECASE)
        and output.affected_area.primary_area_id.value != "PLT-COMPUTE"
    ):
        errors.append(
            "A network partition explicitly affecting the Application Compute Cluster "
            "requires PLT-COMPUTE as the primary affected area."
        )

    direct_message_backlog = _has_direct_message_backlog_evidence(incident)
    if direct_message_backlog:
        if output.incident_category.code != IncidentCategoryCode.PERFORMANCE:
            errors.append(
                "Direct Message Broker backlog evidence requires CAT-PERFORMANCE."
            )
        if output.incident_category.provisional:
            errors.append(
                "Direct Message Broker backlog evidence supports a non-provisional "
                "CAT-PERFORMANCE classification."
            )
        if output.affected_area.primary_area_id.value != "PLT-MESSAGING":
            errors.append(
                "Direct Message Broker backlog evidence requires PLT-MESSAGING as "
                "the primary affected area."
            )
        if output.affected_area.provisional:
            errors.append(
                "Direct Message Broker backlog evidence supports a non-provisional "
                "PLT-MESSAGING affected-area decision."
            )
        reported_ids = {
            item.value for item in incident.reported_affected_service_ids
        }
        additional_ids = {
            item.value for item in output.affected_area.additional_area_ids
        }
        if output.affected_area.primary_area_id.value not in reported_ids and not (
            reported_ids <= additional_ids
        ):
            errors.append(
                "When a dependency platform is primary, all reported affected services "
                "must remain visible as additional affected areas."
            )
        summary_text = output.incident_summary.lower()
        if "no direct impact on the notification service" in summary_text:
            errors.append(
                "The summary must not deny service-level impact when customer "
                "notifications are delayed."
            )
        if not any(
            term in summary_text
            for term in (
                "generally continue to complete",
                "generally complete",
                "not confirmed lost",
                "none are confirmed lost",
            )
        ):
            errors.append(
                "Message-backlog summaries must state the known completion or "
                "message-loss position."
            )

    multi_service = (
        incident.service_impact.impact_scope == ImpactScope.MULTI_SERVICE
        or len(incident.reported_affected_service_ids) > 1
    )
    coordination_required = (
        output.severity.level == SeverityLevel.CRITICAL or multi_service
    )
    if (
        coordination_required
        and output.routing.primary_resolver_group_id != ResolverGroupID.RG_OPS
        and ResolverGroupID.RG_OPS not in output.routing.coordination_group_ids
    ):
        errors.append(
            "Critical or multi-service impact requires RG-OPS as the primary or "
            "coordination group."
        )

    if coordination_required and not any(
        action.common_action_id == "ACT-008" for action in output.initial_actions
    ):
        errors.append(
            "Critical or multi-service impact requires the approved coordination "
            "action ACT-008."
        )

    structured_unknown_present = (
        incident.service_impact.geographic_scope is None
        or getattr(incident.service_impact.workaround_status, "value", "") == "unknown"
        or getattr(incident.service_impact.impact_scope, "value", "") == "unknown"
    )
    conclusive_decisions = not any(
        (
            output.severity.provisional,
            output.incident_category.provisional,
            output.affected_area.provisional,
            output.routing.provisional,
        )
    )
    if (
        not incident.reported_unknowns
        and not structured_unknown_present
        and conclusive_decisions
        and output.information_gaps
    ):
        errors.append(
            "Information gaps must be grounded in explicit or structured unknowns "
            "that materially affect a provisional triage decision."
        )

    if (
        explicit_application_failure
        and output.severity.level in {SeverityLevel.HIGH, SeverityLevel.CRITICAL}
        and incident.service_impact.impact_scope
        in {ImpactScope.SERVICE_WIDE, ImpactScope.WIDESPREAD}
    ):
        impact_description = (
            incident.service_impact.user_impact_description or ""
        )
        percentage_match = re.search(
            r"\b\d+(?:\.\d+)?\s+percent\b",
            impact_description,
            flags=re.IGNORECASE,
        )
        if (
            percentage_match
            and percentage_match.group(0).lower()
            not in output.incident_summary.lower()
        ):
            errors.append(
                "High or Critical service-wide application summaries must preserve "
                "the known impact magnitude."
            )

    geographic_scope = incident.service_impact.geographic_scope
    if (
        geographic_scope
        and output.severity.level in {SeverityLevel.HIGH, SeverityLevel.CRITICAL}
        and geographic_scope.lower() not in output.incident_summary.lower()
    ):
        errors.append(
            "High or Critical incident summaries must include the known geographical scope."
        )

    runbook_ids = {
        action.runbook_id
        for action in output.initial_actions
        if action.runbook_id is not None
    }
    if len(runbook_ids) > 1:
        errors.append("Initial actions must use one primary runbook consistently.")

    for runbook_id in sorted(runbook_ids):
        compatible_categories = RUNBOOK_CATEGORY_COMPATIBILITY.get(runbook_id)
        if (
            compatible_categories is not None
            and output.incident_category.code not in compatible_categories
        ):
            errors.append(
                f"Runbook {runbook_id} is not compatible with category "
                f"{output.incident_category.code.value}."
            )

        if (
            incident.reported_unknowns
            and "ACT-009" in RUNBOOK_RECOMMENDED_ACTIONS.get(runbook_id, set())
            and not any(
                action.common_action_id == "ACT-009"
                for action in output.initial_actions
            )
        ):
            errors.append(
                f"Runbook {runbook_id} recommends ACT-009 when material reported "
                "unknowns remain."
            )

    if (
        not output.incident_category.provisional
        and re.search(
            r"category.{0,40}provisional|severity and category.{0,40}provisional",
            output.uncertainty_statement,
            flags=re.IGNORECASE,
        )
    ):
        errors.append(
            "The uncertainty statement must not describe a conclusive category "
            "decision as provisional."
        )

    if (
        direct_message_backlog
        and incident.reported_unknowns
        and not any(
            action.common_action_id == "ACT-009"
            for action in output.initial_actions
        )
    ):
        errors.append(
            "Message-broker backlog incidents with material reported unknowns "
            "require the cross-cutting evidence-gap action ACT-009."
        )

    if ResolverGroupID.RG_OPS in output.routing.coordination_group_ids:
        rg_ops_allowed = (
            output.severity.level == SeverityLevel.CRITICAL
            or incident.service_impact.impact_scope == ImpactScope.MULTI_SERVICE
            or len(incident.reported_affected_service_ids) > 1
            or output.routing.primary_resolver_group_id == ResolverGroupID.RG_OPS
        )
        if not rg_ops_allowed:
            errors.append(
                "RG-OPS coordination is not justified by Critical severity, multi-service "
                "impact or unclear technical ownership."
            )

    for action in output.initial_actions:
        for pattern in PROHIBITED_ACTION_PATTERNS:
            if re.search(pattern, action.action, flags=re.IGNORECASE):
                errors.append(f"Potentially prohibited action detected: {action.action}")
                break

        cited_action_ids = sorted(
            ref.removeprefix("KB:")
            for ref in action.source_refs
            if re.fullmatch(r"KB:ACT-[0-9]{3}", ref)
        )
        cited_runbook_ids = sorted(
            ref.removeprefix("KB:")
            for ref in action.source_refs
            if re.fullmatch(r"KB:RB-[0-9]{3}", ref)
        )

        if action.common_action_id is None:
            errors.append("Each initial action must populate common_action_id.")
        elif f"KB:{action.common_action_id}" not in action.source_refs:
            errors.append(
                f"Action with common_action_id {action.common_action_id} must cite "
                f"KB:{action.common_action_id}."
            )

        if action.runbook_id is not None and f"KB:{action.runbook_id}" not in action.source_refs:
            errors.append(
                f"Action with runbook_id {action.runbook_id} must cite KB:{action.runbook_id}."
            )

        if action.common_action_id is not None and cited_action_ids:
            if action.common_action_id not in cited_action_ids:
                errors.append(
                    "common_action_id does not match the cited common-action reference."
                )

        if action.runbook_id is not None and cited_runbook_ids:
            if action.runbook_id not in cited_runbook_ids:
                errors.append("runbook_id does not match the cited runbook reference.")

    if output.routing.primary_resolver_group_id in output.routing.coordination_group_ids:
        errors.append("Primary resolver group must not be repeated as a coordination group.")

    if len(set(output.affected_area.additional_area_ids)) != len(
        output.affected_area.additional_area_ids
    ):
        errors.append("Duplicate additional affected-area IDs were returned.")

    if output.affected_area.primary_area_id in output.affected_area.additional_area_ids:
        errors.append("Primary affected-area ID must not be repeated in additional_area_ids.")

    return errors
