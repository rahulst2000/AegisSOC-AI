from pydantic import BaseModel, Field


class AIFinding(BaseModel):
    """Factual finding extracted by AI, grounded in specific evidence IDs."""

    finding: str = Field(..., description="Factual security assertion")
    status: str = Field(..., description="CONFIRMED, LIKELY, UNKNOWN, DISPROVED")
    evidence_ids: list[str] = Field(default_factory=list, description="IDs of SecurityEvents proving this finding")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Certainty score grounded in evidence")
    reasoning_summary: str = Field(default="", description="Forensic reasoning connecting evidence to finding")


class AIHypothesis(BaseModel):
    """Investigation hypothesis evaluated against evidence."""

    hypothesis_id: str = Field(..., description="Identifier (e.g. H1, H2, H3)")
    title: str = Field(..., description="Short descriptive title")
    description: str = Field(..., description="Detailed description of hypothesis")
    status: str = Field(..., description="CONFIRMED, LIKELY, UNKNOWN, DISPROVED")
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)


class AIActionRecommendation(BaseModel):
    """Action recommendation proposed by AI, subject to policy and human approval."""

    action_type: str = Field(
        ..., description="ACCOUNT_LOCKOUT, IP_CONTAINMENT, HOST_ISOLATION, SESSION_REVOCATION, etc."
    )
    target_entity: str = Field(..., description="Target value (e.g. IP address, username, hostname)")
    target_type: str = Field(..., description="IP, USER, HOST, INCIDENT")
    playbook_id: str = Field(..., description="ID of deterministic playbook to execute")
    reason: str = Field(..., description="Evidence-backed justification for action")
    risk_score: int = Field(..., ge=0, le=100)
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)


class AIAnalysisResult(BaseModel):
    """Comprehensive investigation analysis returned by AI provider."""

    executive_summary: str = Field(..., description="High-level incident summary")
    attack_chain: list[str] = Field(default_factory=list, description="Ordered steps of adversary activity")
    findings: list[AIFinding] = Field(default_factory=list)
    hypotheses: list[AIHypothesis] = Field(default_factory=list)
    recommendations: list[AIActionRecommendation] = Field(default_factory=list)
    known_facts: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    l1_decision: str = Field(default="ESCALATE_OR_REMEDIATE")
    l2_escalation_recommended: bool = Field(default=False)
