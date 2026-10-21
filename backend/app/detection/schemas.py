import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DetectionRuleBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=255, description="Rule display name")
    description: str = Field(..., min_length=5, description="Threat description and rationale")
    version: str = Field(default="1.0.0", max_length=50)
    enabled: bool = Field(default=True)
    severity: str = Field(default="MEDIUM", max_length=50, description="LOW, MEDIUM, HIGH, CRITICAL")
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    event_types: list[str] = Field(default_factory=list, description="Target SecurityEvent event_types")
    conditions: dict[str, Any] = Field(default_factory=dict, description="AST selection & filter criteria")
    mitre_tactics: list[str] = Field(default_factory=list, description="Associated MITRE tactics")
    mitre_techniques: list[str] = Field(default_factory=list, description="Associated MITRE techniques")
    tags: list[str] = Field(default_factory=list)


class DetectionRuleCreate(DetectionRuleBase):
    rule_id: str = Field(..., min_length=3, max_length=100, description="Unique rule identifier (e.g. AEGIS-SIG-001)")


class DetectionRuleUpdate(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=255)
    description: str | None = Field(None, min_length=5)
    version: str | None = Field(None, max_length=50)
    enabled: bool | None = None
    severity: str | None = Field(None, max_length=50)
    confidence: float | None = Field(None, ge=0.0, le=1.0)
    event_types: list[str] | None = None
    conditions: dict[str, Any] | None = None
    mitre_tactics: list[str] | None = None
    mitre_techniques: list[str] | None = None
    tags: list[str] | None = None


class DetectionRuleRead(DetectionRuleBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    rule_id: str
    tenant_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class DetectionResultRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: float
    event_ids: list[str]
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    detection_count: int
    previous_occurrences: int
    false_positive_status: str
    analyst_feedback: dict[str, Any]
    timestamp: datetime


class AnalystFeedbackUpdate(BaseModel):
    false_positive_status: str = Field(
        ...,
        description="UNREVIEWED, BENIGN_TRUE_POSITIVE, CONFIRMED_TRUE_POSITIVE, FALSE_POSITIVE",
    )
    comment: str | None = Field(None, max_length=1000)
