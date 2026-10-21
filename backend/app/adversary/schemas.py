import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field


class AuthorizedScope(BaseModel):
    environment: str = Field(default="LAB", description="Must be LAB. PRODUCTION is strictly forbidden.")
    assets: list[str] = Field(default_factory=list, description="Allowed asset identifiers or hostnames")
    hostnames: list[str] = Field(default_factory=list, description="Target hostnames explicitly in scope")
    ips: list[str] = Field(default_factory=list, description="Target IP addresses explicitly in scope")
    allowed_techniques: list[str] = Field(
        default_factory=lambda: ["T1110.001", "T1110.003", "T1078", "T1078.003"],
        description="Allowed MITRE ATT&CK technique IDs",
    )
    prohibited_techniques: list[str] = Field(
        default_factory=lambda: [
            "persistence",
            "data_exfiltration",
            "destructive_actions",
            "credential_dumping",
            "malware_deployment",
        ],
        description="Techniques strictly blocked from simulation",
    )
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC) + timedelta(hours=4),
        description="Expiration timestamp for this authorization window",
    )
    authorized_by: uuid.UUID | None = Field(default=None, description="User ID of authorizer")


class AdversaryAssessmentCreate(BaseModel):
    name: str = Field(..., max_length=255)
    description: str | None = None
    environment: str = Field(default="LAB", description="Target environment (must be LAB)")
    scenario: str = Field(..., description="SCENARIO-001, SCENARIO-002, SCENARIO-003, or SCENARIO-004")
    authorized_scope: AuthorizedScope


class AdversaryAssessmentAuthorize(BaseModel):
    authorized_scope: AuthorizedScope | None = None


class AssessmentResultRead(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    assessment_id: uuid.UUID
    scenario_id: str
    technique_id: str
    target: str
    started_at: datetime
    completed_at: datetime
    simulation_status: str
    detection_status: str
    correlation_status: str
    investigation_status: str
    response_status: str
    verification_status: str
    evidence_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    cleanup_status: str
    overall_result: str
    details: dict[str, Any] = Field(default_factory=dict)

    class Config:
        from_attributes = True


class AdversaryAssessmentRead(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    description: str | None
    environment: str
    scenario: str
    status: str
    authorized_scope: dict[str, Any]
    created_by: uuid.UUID | None
    authorized_by: uuid.UUID | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    results: list[AssessmentResultRead] = Field(default_factory=list)

    class Config:
        from_attributes = True
