from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )


class ServiceComponentID(str, Enum):
    SVC_WEB = "SVC-WEB"
    SVC_API = "SVC-API"
    SVC_AUTH = "SVC-AUTH"
    SVC_ORDER = "SVC-ORDER"
    SVC_PAYMENT = "SVC-PAYMENT"
    SVC_INVENTORY = "SVC-INVENTORY"
    SVC_NOTIFY = "SVC-NOTIFY"
    PLT_COMPUTE = "PLT-COMPUTE"
    PLT_DATABASE = "PLT-DATABASE"
    PLT_MESSAGING = "PLT-MESSAGING"
    PLT_EDGE = "PLT-EDGE"
    PLT_STORAGE = "PLT-STORAGE"
    EXT_PAYMENT = "EXT-PAYMENT"
    EXT_COMMS = "EXT-COMMS"


class ResolverGroupID(str, Enum):
    RG_OPS = "RG-OPS"
    RG_DIGITAL = "RG-DIGITAL"
    RG_NETWORK = "RG-NETWORK"
    RG_IAM = "RG-IAM"
    RG_COMMERCE = "RG-COMMERCE"
    RG_PAYMENTS = "RG-PAYMENTS"
    RG_DATA = "RG-DATA"
    RG_INFRA = "RG-INFRA"
    RG_MESSAGING = "RG-MESSAGING"


class SeverityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class IncidentCategoryCode(str, Enum):
    AVAILABILITY = "CAT-AVAILABILITY"
    PERFORMANCE = "CAT-PERFORMANCE"
    APPLICATION = "CAT-APPLICATION"
    INFRA_NETWORK = "CAT-INFRA-NETWORK"
    DEPENDENCY_CONFIG = "CAT-DEPENDENCY-CONFIG"


class EvidenceSourceType(str, Enum):
    ALERT = "alert"
    LOG = "log"
    METRIC = "metric"
    TRACE = "trace"
    STATUS = "status"
    INCIDENT_RECORD = "incident_record"
    CHANGE_RECORD = "change_record"
    USER_REPORT = "user_report"
    OTHER = "other"


class AvailabilityState(str, Enum):
    UNAVAILABLE = "unavailable"
    SEVERELY_DEGRADED = "severely_degraded"
    PARTIALLY_DEGRADED = "partially_degraded"
    AVAILABLE = "available"
    UNKNOWN = "unknown"


class ImpactScope(str, Enum):
    WIDESPREAD = "widespread"
    MULTI_SERVICE = "multi_service"
    SERVICE_WIDE = "service_wide"
    SUBSET_OF_USERS = "subset_of_users"
    ISOLATED = "isolated"
    UNKNOWN = "unknown"


class WorkaroundStatus(str, Enum):
    NONE = "none"
    LIMITED = "limited"
    AVAILABLE = "available"
    NOT_REQUIRED = "not_required"
    UNKNOWN = "unknown"


class DecisionField(str, Enum):
    SUMMARY = "incident_summary"
    SEVERITY = "severity"
    CATEGORY = "incident_category"
    AFFECTED_AREA = "affected_area"
    ROUTING = "resolver_group"
    INITIAL_ACTIONS = "initial_actions"


class EvidenceItem(StrictModel):
    evidence_id: str = Field(pattern=r"^E[1-9][0-9]*$")
    source_type: EvidenceSourceType
    source_name: str = Field(min_length=1)
    observation: str = Field(min_length=1)
    observed_at: datetime | None = None


class RecentChange(StrictModel):
    change_id: str = Field(pattern=r"^C[1-9][0-9]*$")
    change_type: str = Field(min_length=1)
    description: str = Field(min_length=1)
    occurred_at: datetime | None = None
    confirmed_related_to_incident: bool = False


class ServiceImpact(StrictModel):
    availability_state: AvailabilityState
    impact_scope: ImpactScope
    user_impact_description: str = Field(min_length=1)
    business_function_affected: str | None = None
    affected_user_estimate: int | None = Field(default=None, ge=0)
    geographic_scope: str | None = None
    workaround_status: WorkaroundStatus
    workaround_description: str | None = None
    data_loss_or_corruption_confirmed: bool = False
    serious_security_exposure_confirmed: bool = False


class IncidentInput(StrictModel):
    incident_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    reported_affected_service_ids: list[ServiceComponentID] = Field(min_length=1)
    alert_or_symptom: str = Field(min_length=1)
    technical_evidence: list[EvidenceItem] = Field(min_length=1)
    service_impact: ServiceImpact
    environmental_context: list[str] = Field(default_factory=list)
    recent_changes: list[RecentChange] = Field(default_factory=list)
    reported_unknowns: list[str] = Field(default_factory=list)
    additional_context: list[str] = Field(default_factory=list)


class SeverityAssessment(StrictModel):
    level: SeverityLevel
    rationale: str = Field(min_length=1, max_length=550)
    source_refs: list[str] = Field(min_length=1, max_length=5)
    provisional: bool


class CategoryAssessment(StrictModel):
    code: IncidentCategoryCode
    rationale: str = Field(
        min_length=1,
        max_length=550,
        description="Explain why the category fits without asserting a confirmed cause.",
    )
    source_refs: list[str] = Field(min_length=1, max_length=5)
    provisional: bool


class AffectedAreaAssessment(StrictModel):
    primary_area_id: ServiceComponentID = Field(
        description=(
            "Most directly implicated technical service, platform or dependency. "
            "Place visibly impacted services in additional_area_ids when different."
        )
    )
    additional_area_ids: list[ServiceComponentID] = Field(max_length=4)
    rationale: str = Field(min_length=1, max_length=550)
    source_refs: list[str] = Field(min_length=1, max_length=5)
    provisional: bool


class RoutingRecommendation(StrictModel):
    primary_resolver_group_id: ResolverGroupID
    coordination_group_ids: list[ResolverGroupID] = Field(max_length=3)
    rationale: str = Field(min_length=1, max_length=550)
    source_refs: list[str] = Field(min_length=1, max_length=5)
    provisional: bool


class InitialAction(StrictModel):
    action: str = Field(min_length=1, max_length=300)
    rationale: str = Field(min_length=1, max_length=450)
    source_refs: list[str] = Field(
        min_length=2,
        max_length=5,
        description=(
            "Include relevant incident evidence plus the exact KB:RB-* or KB:ACT-* "
            "reference represented by the identifier fields."
        ),
    )
    runbook_id: str | None = Field(default=None, pattern=r"^RB-[0-9]{3}$")
    common_action_id: str | None = Field(default=None, pattern=r"^ACT-[0-9]{3}$")


class InformationGap(StrictModel):
    missing_information: str = Field(min_length=1, max_length=350)
    why_needed: str = Field(min_length=1, max_length=450)
    affected_decisions: list[DecisionField] = Field(min_length=1, max_length=6)
    requested_evidence: str = Field(min_length=1, max_length=400)


class TriageOutput(StrictModel):
    incident_id: str = Field(min_length=1)
    incident_summary: str = Field(
        min_length=1,
        max_length=750,
        description=(
            "One to three concise sentences covering visible impact, key evidence "
            "and the directly implicated area without asserting a root cause."
        ),
    )
    summary_source_refs: list[str] = Field(min_length=1, max_length=5)
    severity: SeverityAssessment
    incident_category: CategoryAssessment
    affected_area: AffectedAreaAssessment
    routing: RoutingRecommendation
    initial_actions: list[InitialAction] = Field(min_length=2, max_length=5)
    information_gaps: list[InformationGap] = Field(max_length=6)
    uncertainty_statement: str = Field(min_length=1, max_length=550)
    advisory_only: Literal[True] = True
    definitive_root_cause_established: Literal[False] = False


def export_json_schemas(output_directory: str = "schema_exports") -> None:
    output_path = Path(output_directory)
    output_path.mkdir(parents=True, exist_ok=True)

    (output_path / "incident_input_schema.json").write_text(
        json.dumps(IncidentInput.model_json_schema(), indent=2),
        encoding="utf-8",
    )
    (output_path / "triage_output_schema.json").write_text(
        json.dumps(TriageOutput.model_json_schema(), indent=2),
        encoding="utf-8",
    )


if __name__ == "__main__":
    export_json_schemas()
