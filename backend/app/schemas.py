from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


NetworkMode = Literal["offline", "manual", "scheduled"]


class SettingsUpdate(BaseModel):
    network_mode: NetworkMode
    profile: dict = Field(default_factory=dict)


class ActionCreate(BaseModel):
    title: str = Field(min_length=3, max_length=240)
    action_type: Literal["Read", "Investigate", "Hunt", "Detect", "Patch", "Monitor", "Brief", "Archive", "Assess"] = "Investigate"
    priority: Literal["critical", "high", "medium", "low"] = "medium"
    linked_reference: str | None = None
    notes: str | None = None
    due_at: datetime | None = None


class DetectionCreate(BaseModel):
    title: str = Field(min_length=3, max_length=240)
    description: str = Field(min_length=3)
    rule_format: Literal["Sigma", "Microsoft Sentinel KQL", "Generic pseudocode"]
    rule_content: str = Field(min_length=3)
    attack_techniques: list[str] = Field(default_factory=list)
    required_telemetry: list[str] = Field(default_factory=list)


class DetectionMaturityUpdate(BaseModel):
    maturity: Literal["draft", "reviewed", "tested", "validated", "deployed", "tuned", "monitored", "retired"]
    owner: str = Field(default="", max_length=240)
    telemetry_state: Literal["unknown", "unavailable", "available", "normalized"] = "unknown"
    validation_notes: str = Field(default="", max_length=5000)


class DetectionValidationCreate(BaseModel):
    fixture_name: str = Field(min_length=2, max_length=240)
    outcome: Literal["pass", "fail", "not_run"]
    evidence: str = Field(default="", max_length=5000)


class DetectionLabRunCreate(BaseModel):
    fixture_id: Literal["expected-signal", "benign-look-alike", "missing-telemetry"]


class CaseEvidenceCreate(BaseModel):
    evidence_type: Literal["fact", "claim", "inference", "artifact", "decision"]
    content: str = Field(min_length=2, max_length=10000)
    source_url: str | None = Field(default=None, max_length=2048)


class HuntFindingCreate(BaseModel):
    classification: Literal["no_finding", "benign", "suspicious", "confirmed", "detection_candidate"]
    summary: str = Field(min_length=2, max_length=5000)
    linked_detection_id: str | None = None


class ConnectorUpdate(BaseModel):
    enabled: bool
    schedule_hours: int | None = Field(default=None, ge=1, le=720)
    acknowledged_network_disclosure: bool = False


class BulkConnectorUpdate(BaseModel):
    enabled: bool
    acknowledged_network_disclosure: bool = False


class SyncRequest(BaseModel):
    confirmed: bool = False


class RawContentPurgeRequest(BaseModel):
    confirmation: Literal["PURGE"]


class DeletionConfirmation(BaseModel):
    confirmation: Literal["DELETE"]


class DigestCreate(BaseModel):
    title: str = Field(default="Local threat intelligence briefing", min_length=3, max_length=240)
    audience: Literal["Executive", "Analyst", "Technical"] = "Analyst"


class CopilotRequest(BaseModel):
    question: str = Field(min_length=3, max_length=4000)
    approve_external: bool = False


class SemanticReindexRequest(BaseModel):
    confirmation: Literal["REINDEX"]


class AccessPassword(BaseModel):
    password: str = Field(min_length=12, max_length=1024)


class TechnologyProfileCreate(BaseModel):
    name: str = Field(min_length=2, max_length=240)
    vendor: str = Field(default="", max_length=240)
    product: str = Field(default="", max_length=240)
    version: str = Field(default="", max_length=120)
    criticality: Literal["critical", "high", "medium", "low"] = "medium"
    internet_exposed: bool = False
    status: Literal["active", "retired", "unknown"] = "active"
    notes: str = Field(default="", max_length=3000)


class RelevanceAssessmentUpdate(BaseModel):
    entity_type: Literal["vulnerability", "threat", "ioc"]
    reference_id: str = Field(min_length=2, max_length=240)
    status: Literal["unknown", "potential", "confirmed", "not_applicable"]
    evidence: str = Field(default="", max_length=5000)
    review_at: datetime | None = None


class IocCreate(BaseModel):
    indicator_type: Literal["ip", "domain", "url", "hash", "email", "other"]
    value: str = Field(min_length=2, max_length=2048)
    lifecycle_status: Literal["observed", "suspicious", "malicious", "stale", "expired", "sinkholed", "false_positive"] = "observed"
    confidence: Literal["unconfirmed", "source-reported", "corroborated", "analyst-confirmed"] = "source-reported"
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    valid_until: datetime | None = None
    source_url: str | None = Field(default=None, max_length=2048)
    notes: str = Field(default="", max_length=5000)


class IocUpdate(BaseModel):
    lifecycle_status: Literal["observed", "suspicious", "malicious", "stale", "expired", "sinkholed", "false_positive"]
    confidence: Literal["unconfirmed", "source-reported", "corroborated", "analyst-confirmed"]
    valid_until: datetime | None = None
    notes: str = Field(default="", max_length=5000)


class WatchlistCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=1000)
    color: Literal["cyan", "amber", "purple", "red"] = "cyan"


class WatchlistItemCreate(BaseModel):
    entity_type: Literal["threat", "vulnerability", "ioc", "detection"]
    reference_id: str = Field(min_length=2, max_length=240)
    title: str = Field(default="", max_length=500)
    notes: str = Field(default="", max_length=2000)


class HuntCaseCreate(BaseModel):
    name: str = Field(min_length=3, max_length=240)
    objective: str = Field(min_length=3, max_length=3000)
    hypothesis: str = Field(min_length=3, max_length=3000)
    scope: str = Field(default="", max_length=2000)
    status: Literal["planned", "active", "complete", "escalated"] = "planned"
    attack_techniques: list[str] = Field(default_factory=list)
    required_telemetry: list[str] = Field(default_factory=list)
    linked_reference: str | None = Field(default=None, max_length=240)
    notes: str = Field(default="", max_length=5000)


class HuntStatusUpdate(BaseModel):
    status: Literal["planned", "active", "complete", "escalated"]


class IncidentCaseCreate(BaseModel):
    title: str = Field(min_length=3, max_length=240)
    summary: str = Field(min_length=3, max_length=3000)
    severity: Literal["critical", "high", "medium", "low"] = "medium"
    status: Literal["open", "investigating", "contained", "closed"] = "open"
    linked_reference: str | None = Field(default=None, max_length=240)
    notes: str = Field(default="", max_length=5000)
    tags: list[str] = Field(default_factory=list)


class IncidentStatusUpdate(BaseModel):
    status: Literal["open", "investigating", "contained", "closed"]
