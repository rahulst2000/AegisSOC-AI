from dataclasses import dataclass, field


@dataclass
class HypothesisItem:
    """Represents an investigated hypothesis."""

    hypothesis_id: str  # H1, H2, etc.
    title: str
    description: str
    status: str  # CONFIRMED, LIKELY, UNKNOWN, DISPROVED
    confidence: float = 0.0
    evidence_ids: list[str] = field(default_factory=list)
    supporting_evidence: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
