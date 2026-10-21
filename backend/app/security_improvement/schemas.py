import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SecurityFindingCreate(BaseModel):
    assessment_id: uuid.UUID | None = None
    severity: str = Field(default="MEDIUM", description="CRITICAL, HIGH, MEDIUM, LOW, INFO")
    title: str = Field(..., max_length=255)
    description: str
    asset: str
    technique: str
    evidence_ids: list[str] = Field(default_factory=list)
    root_cause: str
    business_impact: str
    recommendation: str
    priority: str = Field(default="P2", description="P1, P2, P3, P4")
    owner: str = "Security Engineering"


class RemediationActionCreate(BaseModel):
    proposed_change: str
    change_type: str = Field(default="RULE_UPDATE", description="RULE_UPDATE, POLICY_UPDATE, ASSET_CONFIG")
    details: dict[str, Any] = Field(default_factory=dict)


class RemediationActionRead(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    finding_id: uuid.UUID
    proposed_change: str
    change_type: str
    approval_status: str
    approved_by: uuid.UUID | None
    applied_at: datetime | None
    retest_assessment_id: uuid.UUID | None
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    class Config:
        from_attributes = True


class SecurityFindingRead(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    assessment_id: uuid.UUID | None
    severity: str
    title: str
    description: str
    asset: str
    technique: str
    evidence_ids: list[str] = Field(default_factory=list)
    root_cause: str
    business_impact: str
    recommendation: str
    priority: str
    owner: str
    status: str
    created_at: datetime
    updated_at: datetime
    remediations: list[RemediationActionRead] = Field(default_factory=list)

    class Config:
        from_attributes = True


class DetectionGapReport(BaseModel):
    gap_type: str = Field(
        ...,
        description="DETECTION_GAP, CORRELATION_GAP, INVESTIGATION_GAP, RESPONSE_GAP, VERIFICATION_GAP",
    )
    technique_id: str
    target: str
    severity: str
    summary: str
    recommendation: str
    assessment_id: str
    scenario_id: str


class MitreCoverageItem(BaseModel):
    technique_id: str
    technique_name: str
    tactics: list[str] = Field(default_factory=list)
    simulation: str
    detection: str
    correlation: str
    investigation: str
    response: str
    verification: str
    overall: str


class SecurityPostureScore(BaseModel):
    category: str
    tested_techniques: int
    successful_detections: int
    coverage_percentage: float
    status: str


class SecurityPostureReport(BaseModel):
    test_coverage_percentage: float
    overall_posture_score: float
    categories: list[SecurityPostureScore]
    total_findings_open: int
    total_findings_remediated: int
    remediation_success_rate: float
