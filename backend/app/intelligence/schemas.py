"""Pydantic schemas for Phase 5B Advanced Security Intelligence."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# 5B-01: Security State Model
class SecurityStateResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    timestamp: datetime
    risk_score: float
    posture_score: float
    open_incidents_count: int
    active_alerts_count: int
    monitored_assets_count: int
    monitored_identities_count: int
    state_vector: dict[str, Any]
    state_hash: str
    created_at: datetime


class SecurityStateTransitionResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    timestamp: datetime
    trigger_type: str
    trigger_entity_id: str | None = None
    from_state_summary: str
    to_state_summary: str
    risk_delta: float
    posture_delta: float
    evidence_references: list[dict[str, Any]]
    rationale: str
    confidence: float


# 5B-02: Attack Trajectory
class TrajectoryStagePrediction(BaseModel):
    stage: str
    probability: float
    rationale: str


class ObservedStageRecord(BaseModel):
    stage: str
    timestamp: str
    evidence_event_ids: list[str]


class AttackTrajectoryResponse(BaseModel):
    incident_id: uuid.UUID
    current_stage: str
    observed_stages: list[ObservedStageRecord]
    predicted_next_stages: list[TrajectoryStagePrediction]
    confidence: float
    evidence_event_ids: list[str]
    updated_at: datetime


# 5B-03: Attack Graph
class AttackGraphNode(BaseModel):
    id: str
    type: str  # SOURCE_IP, USER, HOST, PROCESS, FILE, NETWORK, INCIDENT, MITRE_TECHNIQUE
    label: str
    properties: dict[str, Any] = Field(default_factory=dict)
    evidence_id: str | None = None
    timestamp: str | None = None


class AttackGraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relationship: str  # AUTHENTICATED_AS, LOGGED_INTO, SPAWNED, ACCESSED, COMMUNICATED_WITH, MAPPED_TO, etc.
    evidence_id: str | None = None
    timestamp: str | None = None


class AttackGraphResponse(BaseModel):
    tenant_id: uuid.UUID
    incident_id: uuid.UUID | None = None
    nodes: list[AttackGraphNode]
    edges: list[AttackGraphEdge]
    metadata: dict[str, Any] = Field(default_factory=dict)


# 5B-04: Why Now Engine
class WhyNowResponse(BaseModel):
    incident_id: uuid.UUID
    what_changed: str
    why_it_matters: str
    evidence: list[dict[str, Any]]
    confidence: float
    evaluated_at: datetime


# 5B-05: What Changed Engine
class BaselineComparisonItem(BaseModel):
    dimension: str  # LOGIN_TIME, SOURCE_IP, PROCESS_NAME, COMMAND_LINE, USER_AGENT
    observed_value: str
    historical_baseline: str
    is_anomaly: bool
    evidence_event_id: str
    timestamp: str


class WhatChangedResponse(BaseModel):
    entity_type: str  # USER, HOST, IP
    entity_id: str
    time_window: str
    anomalies_detected: int
    comparisons: list[BaselineComparisonItem]
    confidence: float
    evaluated_at: datetime


# 5B-06: Counterfactual Security Analysis
class CounterfactualRequest(BaseModel):
    incident_id: uuid.UUID
    simulated_action: str  # DO_NOTHING, ISOLATE_HOST, REVOKE_SESSION, DISABLE_ACCOUNT
    action_parameters: dict[str, Any] = Field(default_factory=dict)


class CounterfactualResponse(BaseModel):
    incident_id: uuid.UUID
    current_state: str
    action_simulated: str
    predicted_state: str
    risk_change: float
    business_impact: str
    assumptions: list[str]
    confidence: float
    simulated_at: datetime


# 5B-07: Security Digital Twin
class DigitalTwinAsset(BaseModel):
    id: str
    hostname: str
    ip_address: str
    criticality: str
    dependencies: list[str]
    active_controls: list[str]
    vulnerabilities: list[str]


class BlastRadiusResponse(BaseModel):
    seed_node: str
    seed_type: str
    direct_dependencies: list[str]
    transitive_blast_radius: list[str]
    total_impacted_assets: int
    critical_assets_at_risk: list[str]
    isolation_recommended: bool


class DigitalTwinResponse(BaseModel):
    tenant_id: uuid.UUID
    total_assets: int
    total_identities: int
    total_trust_edges: int
    assets: list[DigitalTwinAsset]
    topology_summary: dict[str, Any]


# 5B-08: Organizational Security Memory
class MemoryEntryCreate(BaseModel):
    category: str
    title: str
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    evidence_references: list[str] = Field(default_factory=list)
    confidence: float = 1.0


class MemoryEntryResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    category: str
    title: str
    summary: str
    details: dict[str, Any]
    tags: list[str]
    evidence_references: list[str]
    confidence: float
    created_at: datetime


# 5B-09: Advanced Threat Intelligence
class ThreatIntelLookupRequest(BaseModel):
    indicator_type: str  # IP, DOMAIN, URL, HASH
    indicator_value: str
    local_context: dict[str, Any] = Field(default_factory=dict)


class ThreatIntelLookupResponse(BaseModel):
    indicator_type: str
    indicator_value: str
    reputation_score: float
    threat_type: str
    source_provider: str
    tags: list[str]
    local_behavior_factor: float
    asset_criticality_factor: float
    hybrid_risk_score: float
    maliciousness_verdict: str  # MALICIOUS, SUSPICIOUS, BENIGN, UNKNOWN
    rationale: str
    evidence_grounded: bool


# 5B-10: Continuous Security Improvement
class CandidateCreate(BaseModel):
    incident_id: uuid.UUID | None = None
    title: str
    rationale: str
    proposed_rule_yaml: str
    mitre_techniques: list[str] = Field(default_factory=list)


class CandidateResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    incident_id: uuid.UUID | None = None
    title: str
    rationale: str
    mitre_techniques: list[str]
    proposed_rule_yaml: str
    test_results: dict[str, Any]
    status: str
    created_at: datetime
    reviewed_by: uuid.UUID | None = None
    reviewed_at: datetime | None = None


# 5B-11: Continuous Adversary Schedule
class ScheduleCreate(BaseModel):
    name: str
    scenario_id: str
    cron_expression: str = "0 2 * * 1"
    environment: str = "LAB"
    authorized_scope: dict[str, Any]
    target_allowlist: list[str]
    technique_allowlist: list[str]
    expires_at: datetime


class ScheduleResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    scenario_id: str
    cron_expression: str
    environment: str
    authorized_scope: dict[str, Any]
    target_allowlist: list[str]
    technique_allowlist: list[str]
    is_active: bool
    expires_at: datetime
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    created_at: datetime


# 5B-12: End-to-End MITRE Pipeline Coverage
class MitrePipelineStageCoverage(BaseModel):
    technique_id: str
    technique_name: str
    tactics: list[str]
    simulation: str
    detection: str
    correlation: str
    investigation: str
    response: str
    verification: str
    pipeline_completed: bool
    evidence_ids: list[str]


class MitrePipelineCoverageReport(BaseModel):
    tenant_id: uuid.UUID
    total_techniques_in_scope: int
    fully_verified_techniques: int
    pipeline_coverage_percentage: float
    coverage_matrix: list[MitrePipelineStageCoverage]
    identified_gaps: list[dict[str, Any]]


# 5B-13: GRC Intelligence
class GrcControlItem(BaseModel):
    id: uuid.UUID
    framework: str
    control_id: str
    control_name: str
    domain: str
    status: str
    evidence_references: list[dict[str, Any]]
    gap_description: str | None = None
    risk_level: str
    remediation_plan: str | None = None
    verification_method: str
    updated_at: datetime


class GrcFrameworkSummary(BaseModel):
    framework: str
    total_controls: int
    compliant_controls: int
    partially_compliant_controls: int
    non_compliant_controls: int
    compliance_score_percentage: float
    controls: list[GrcControlItem]


# 5B-14: Executive Security Posture
class DomainPostureScore(BaseModel):
    domain: str
    score: float
    status: str  # OPTIMAL, ACCEPTABLE, DEFICIENT, CRITICAL
    evidence_summary: str
    key_findings_count: int


class ExecutivePostureReport(BaseModel):
    tenant_id: uuid.UUID
    generated_at: datetime
    overall_posture_score: float
    overall_status: str
    posture_trend: str  # IMPROVING, STABLE, DECLINING
    domain_scores: list[DomainPostureScore]
    top_strategic_priorities: list[str]
    evidence_backed_assurance: str
