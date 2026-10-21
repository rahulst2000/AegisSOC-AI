from dataclasses import dataclass, field


@dataclass
class FindingItem:
    """Represents a factual finding backed by evidence."""

    finding: str
    status: str  # CONFIRMED, LIKELY, UNKNOWN, DISPROVED
    evidence_ids: list[str] = field(default_factory=list)
    confidence: float = 0.0
    reasoning_summary: str = ""
