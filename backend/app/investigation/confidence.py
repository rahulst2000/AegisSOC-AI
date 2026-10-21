def calculate_investigation_confidence(
    base_rule_confidences: list[float],
    verified_evidence_count: int,
    independent_signal_count: int,
    contradicting_evidence_count: int = 0,
    unknowns_count: int = 0,
    evidence_tampered: bool = False,
) -> float:
    """
    Computes a deterministic investigation confidence score between 0.0 and 1.0.

    FORMULA:
    Confidence = clamp(
        0.0, 1.0,
        BaseConfidence * (1.0 + EvidenceBonus + SignalBonus - ContradictionPenalty - UnknownsPenalty)
    )

    Where:
    - BaseConfidence: Mean confidence of underlying detection rules (default 0.50)
    - EvidenceBonus: min(0.20, 0.02 * verified_evidence_count)
    - SignalBonus: min(0.15, 0.05 * max(0, independent_signal_count - 1))
    - ContradictionPenalty: 0.25 * contradicting_evidence_count
    - UnknownsPenalty: 0.05 * unknowns_count
    - EvidenceTampered: Forces confidence to 0.10 max if hash mismatch detected.
    """
    if evidence_tampered:
        return 0.10

    if verified_evidence_count == 0:
        return 0.15

    base = sum(base_rule_confidences) / len(base_rule_confidences) if base_rule_confidences else 0.50

    evidence_bonus = min(0.20, 0.02 * verified_evidence_count)
    signal_bonus = min(0.15, 0.05 * max(0, independent_signal_count - 1))
    contradiction_penalty = 0.25 * contradicting_evidence_count
    unknowns_penalty = 0.05 * unknowns_count

    raw_score = base * (1.0 + evidence_bonus + signal_bonus - contradiction_penalty - unknowns_penalty)
    return round(max(0.0, min(1.0, raw_score)), 2)
