import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class InvestigationFindingRead(BaseModel):
    id: uuid.UUID
    investigation_id: uuid.UUID
    tenant_id: uuid.UUID
    finding: str
    status: str
    evidence_ids: list[str]
    confidence: float
    reasoning_summary: str
    created_at: datetime

    class Config:
        from_attributes = True


class InvestigationHypothesisRead(BaseModel):
    id: uuid.UUID
    investigation_id: uuid.UUID
    tenant_id: uuid.UUID
    hypothesis_id: str
    title: str
    description: str
    status: str
    confidence: float
    evidence_ids: list[str]
    supporting_evidence: list[str]
    contradicting_evidence: list[str]
    unknowns: list[str]
    created_at: datetime

    class Config:
        from_attributes = True


class InvestigationRead(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    tenant_id: uuid.UUID
    status: str
    executive_summary: str
    attack_chain: list[str]
    known_facts: list[str]
    unknowns: list[str]
    recommended_next_steps: list[str]
    l1_decision: str
    l2_escalation_recommended: bool
    risk_score: int
    confidence_score: float
    created_at: datetime
    updated_at: datetime
    hypotheses: list[InvestigationHypothesisRead] = []
    findings: list[InvestigationFindingRead] = []

    class Config:
        from_attributes = True


class InvestigationCreateRequest(BaseModel):
    """Optional parameters when triggering an investigation."""

    force_refresh: bool = Field(default=False, description="Re-run investigation even if existing record exists")
    analyst_notes: str | None = Field(default=None, max_length=1000)
