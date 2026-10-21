import re

from app.ai.schemas import AIActionRecommendation, AIAnalysisResult, AIFinding, AIHypothesis
from app.core.logging import logger

# Disallowed / dangerous instruction patterns inside untrusted data
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(in\s+)?(unrestricted|dan|god|developer)\s+mode", re.IGNORECASE),
    re.compile(r"system\s*:\s*override", re.IGNORECASE),
    re.compile(r"disable\s+(the\s+)?(firewall|security|antivirus|edr|audit)", re.IGNORECASE),
    re.compile(r"grant\s+(me\s+)?(admin|root|superuser|access)", re.IGNORECASE),
    re.compile(r"drop\s+(table|database)|delete\s+from\s+users", re.IGNORECASE),
    re.compile(r"cat\s+/etc/shadow|eval\s*\(|exec\s*\(", re.IGNORECASE),
]

ALLOWED_ACTION_TYPES = {
    "ACCOUNT_LOCKOUT",
    "IP_CONTAINMENT",
    "SESSION_REVOCATION",
    "HOST_ISOLATION",
    "L2_ESCALATION",
    "COLLECT_EVIDENCE",
}


def detect_prompt_injection(text: str) -> list[str]:
    """
    Scans a string (from event logs, usernames, commands, etc.) for prompt-injection signatures.
    Returns matched attack patterns.
    """
    if not text:
        return []

    detected: list[str] = []
    for pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            detected.append(pattern.pattern)
    return detected


def validate_and_sanitize_ai_result(
    result: AIAnalysisResult,
    valid_event_ids: set[str],
) -> AIAnalysisResult:
    """
    Validates that the AI result complies with forensic integrity rules:
    1. Every referenced evidence ID must exist in valid_event_ids.
    2. Any finding referencing invalid evidence is downgraded to 'UNKNOWN'.
    3. Action recommendations must belong to the allowlisted playbooks.
    4. Unsupported hypotheses are adjusted to 'UNKNOWN'.
    """
    validated_findings: list[AIFinding] = []
    for finding in result.findings:
        # Check referenced evidence
        invalid_ids = [eid for eid in finding.evidence_ids if eid not in valid_event_ids]
        if invalid_ids:
            logger.warning(
                "AI finding cited invalid or fabricated evidence IDs: %s. Downgrading finding to UNKNOWN.",
                invalid_ids,
            )
            # Filter to only valid IDs
            sanitized_ids = [eid for eid in finding.evidence_ids if eid in valid_event_ids]
            validated_findings.append(
                AIFinding(
                    finding=finding.finding,
                    status="UNKNOWN" if not sanitized_ids else finding.status,
                    evidence_ids=sanitized_ids,
                    confidence=min(finding.confidence, 0.3) if not sanitized_ids else finding.confidence,
                    reasoning_summary=(
                        f"{finding.reasoning_summary} [Warning: Cited non-existent evidence {invalid_ids}]"
                    ),
                )
            )
        else:
            validated_findings.append(finding)

    validated_hypotheses: list[AIHypothesis] = []
    for hyp in result.hypotheses:
        sanitized_ids = [eid for eid in hyp.evidence_ids if eid in valid_event_ids]
        status = hyp.status
        if hyp.status in ("CONFIRMED", "LIKELY") and not sanitized_ids:
            # Cannot confirm hypothesis without valid evidence
            status = "UNKNOWN"

        validated_hypotheses.append(
            AIHypothesis(
                hypothesis_id=hyp.hypothesis_id,
                title=hyp.title,
                description=hyp.description,
                status=status,
                confidence=hyp.confidence if sanitized_ids else min(hyp.confidence, 0.2),
                evidence_ids=sanitized_ids,
                supporting_evidence=hyp.supporting_evidence,
                contradicting_evidence=hyp.contradicting_evidence,
                unknowns=hyp.unknowns,
            )
        )

    validated_recommendations: list[AIActionRecommendation] = []
    for rec in result.recommendations:
        if rec.action_type not in ALLOWED_ACTION_TYPES:
            logger.warning(
                "Disallowed action type '%s' in AI recommendation. Dropping recommendation.", rec.action_type
            )
            continue
        sanitized_ids = [eid for eid in rec.evidence_ids if eid in valid_event_ids]
        validated_recommendations.append(
            AIActionRecommendation(
                action_type=rec.action_type,
                target_entity=rec.target_entity,
                target_type=rec.target_type,
                playbook_id=rec.playbook_id,
                reason=rec.reason,
                risk_score=rec.risk_score,
                confidence=rec.confidence,
                evidence_ids=sanitized_ids,
            )
        )

    return AIAnalysisResult(
        executive_summary=result.executive_summary,
        attack_chain=result.attack_chain,
        findings=validated_findings,
        hypotheses=validated_hypotheses,
        recommendations=validated_recommendations,
        known_facts=result.known_facts,
        unknowns=result.unknowns,
        recommended_next_steps=result.recommended_next_steps,
        l1_decision=result.l1_decision,
        l2_escalation_recommended=result.l2_escalation_recommended,
    )
