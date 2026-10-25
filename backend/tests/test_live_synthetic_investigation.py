"""
Phase 5A Live Synthetic AI Investigation Test (Section 19).

Verifies the end-to-end controlled autonomous pipeline:
Telemetry -> Detection -> Correlation -> Investigation -> Gemini Analysis ->
Evidence Validation -> Risk/Confidence -> Policy & Recommendation Gate.

Strict Safeguards:
1. AI cites actual available evidence.
2. AI does NOT directly execute containment.
3. Policy engine and human approval remain mandatory.
4. Uses synthetic events only.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.gemini_provider import GeminiAIProvider
from app.ai.schemas import AIActionRecommendation, AIAnalysisResult, AIFinding, AIHypothesis
from app.investigation.investigator import run_investigation
from app.investigation.service import get_recommendations_by_incident
from app.models.event import SecurityEvent
from app.models.incident import Incident
from app.models.tenant import Tenant


@pytest.mark.asyncio
async def test_live_synthetic_investigation_pipeline(db_session: AsyncSession):
    """
    Simulates a synthetic attack scenario:
    Multiple failed SSH authentication attempts followed by a successful login.
    Traces execution through full evidence validation and human approval gate.
    """
    # 1. Setup Tenant
    tenant = Tenant(name="Live Synthetic SOC Tenant")
    db_session.add(tenant)
    await db_session.flush()

    base_time = datetime.now(UTC)
    source_ip = "198.51.100.42"
    target_user = "admin"
    target_host = "bastion-prod-01"

    # 2. Ingest Synthetic Telemetry Events (3 failures + 1 success)
    events: list[SecurityEvent] = []
    for i in range(3):
        fail_evt = SecurityEvent(
            tenant_id=tenant.id,
            source="sshd",
            event_type="authentication_failure",
            severity="MEDIUM",
            source_ip=source_ip,
            username=target_user,
            hostname=target_host,
            timestamp=base_time + timedelta(seconds=i * 2),
            raw_event={"auth": {"result": "failure", "method": "password"}},
            normalized_event={
                "event": {"type": "authentication_failure", "category": "authentication"},
                "source": {"ip": source_ip},
                "user": {"name": target_user},
                "host": {"hostname": target_host},
            },
        )
        db_session.add(fail_evt)
        events.append(fail_evt)

    succ_evt = SecurityEvent(
        tenant_id=tenant.id,
        source="sshd",
        event_type="authentication_success",
        severity="HIGH",
        source_ip=source_ip,
        username=target_user,
        hostname=target_host,
        timestamp=base_time + timedelta(seconds=10),
        raw_event={"auth": {"result": "success", "method": "password"}},
        normalized_event={
            "event": {"type": "authentication_success", "category": "authentication"},
            "source": {"ip": source_ip},
            "user": {"name": target_user},
            "host": {"hostname": target_host},
        },
    )
    db_session.add(succ_evt)
    events.append(succ_evt)
    await db_session.flush()

    event_ids = [str(e.id) for e in events]

    # 3. Correlation: Create Incident
    incident = Incident(
        tenant_id=tenant.id,
        title="Failure Then Success Authentication Anomaly",
        description=f"Multiple failed logins from {source_ip} followed by successful authentication for user {target_user}.",
        severity="HIGH",
        status="OPEN",
        risk_score=85,
        confidence=0.88,
        mitre_techniques=["T1110.001", "T1078.003"],
        source_ips=[source_ip],
        affected_users=[target_user],
        affected_assets=[target_host],
    )
    db_session.add(incident)
    await db_session.flush()

    # 4. Configure Gemini AI Provider with structured synthetic response
    gemini_provider = GeminiAIProvider(api_key="test-live-synthetic-mock-key-12345")

    mock_gemini_analysis = AIAnalysisResult(
        executive_summary=(
            f"Adversary from {source_ip} conducted an SSH brute force attack against user '{target_user}' "
            f"on '{target_host}', successfully gaining access."
        ),
        attack_chain=[
            f"1. Password guessing attempts from {source_ip}",
            f"2. Successful authentication as {target_user}",
        ],
        findings=[
            AIFinding(
                finding="Brute force authentication sequence from untrusted external IP",
                status="CONFIRMED",
                evidence_ids=event_ids[:3],
                confidence=0.92,
                reasoning_summary="Evidence events indicate repeated authentication failures.",
            ),
            AIFinding(
                finding="Unauthorized access gained using valid credentials",
                status="CONFIRMED",
                evidence_ids=[event_ids[3]],
                confidence=0.89,
                reasoning_summary="Evidence event confirms successful authentication after failures.",
            ),
        ],
        hypotheses=[
            AIHypothesis(
                hypothesis_id="H2",
                title="Compromised Account",
                description=f"Valid credentials for '{target_user}' were obtained through brute force.",
                status="CONFIRMED",
                confidence=0.90,
                evidence_ids=event_ids,
            )
        ],
        recommendations=[
            AIActionRecommendation(
                action_type="IP_CONTAINMENT",
                target_entity=source_ip,
                target_type="IP",
                playbook_id="PLAYBOOK-002",
                reason=f"Block malicious source IP {source_ip} at perimeter firewall.",
                risk_score=85,
                confidence=0.92,
                evidence_ids=event_ids[:3],
            ),
            AIActionRecommendation(
                action_type="ACCOUNT_LOCKOUT",
                target_entity=target_user,
                target_type="USER",
                playbook_id="PLAYBOOK-001",
                reason=f"Temporarily suspend compromised account '{target_user}' pending password reset.",
                risk_score=80,
                confidence=0.88,
                evidence_ids=[event_ids[3]],
            ),
        ],
        known_facts=[f"Source IP: {source_ip}", f"User: {target_user}"],
        unknowns=[],
        recommended_next_steps=["Revoke active sessions", "Reset credentials"],
        l1_decision="ESCALATE_OR_REMEDIATE",
        l2_escalation_recommended=True,
    )

    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = mock_gemini_analysis.model_dump_json()
    mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)

    # 5. Execute Autonomous Investigation
    with patch("app.investigation.investigator.get_ai_provider", return_value=gemini_provider):
        with patch.object(gemini_provider, "_get_client", return_value=mock_client):
            investigation = await run_investigation(
                db=db_session,
                tenant_id=tenant.id,
                incident_id=incident.id,
                analyst_notes="Live synthetic verification run.",
            )

    # 6. Verify Investigation Record and Evidence Grounding
    assert investigation is not None
    assert investigation.incident_id == incident.id
    assert investigation.tenant_id == tenant.id
    assert investigation.confidence_score > 0.0

    # Ensure findings were saved and evidence IDs are verified
    assert len(investigation.findings) == 2
    for finding in investigation.findings:
        assert finding.status == "CONFIRMED"
        assert len(finding.evidence_ids) > 0
        for eid in finding.evidence_ids:
            assert eid in event_ids  # Evidence strictly grounded!

    assert len(investigation.hypotheses) == 1
    assert investigation.hypotheses[0].hypothesis_id == "H2"
    assert investigation.hypotheses[0].status == "CONFIRMED"

    # 7. Verify Policy Engine & Containment Safety (NO direct containment)
    with patch("app.investigation.service.get_ai_provider", return_value=gemini_provider):
        with patch.object(gemini_provider, "_get_client", return_value=mock_client):
            recs = await get_recommendations_by_incident(db_session, tenant.id, incident.id)
            assert len(recs) == 2
            rec_actions = {r.action_type for r in recs}
            assert "IP_CONTAINMENT" in rec_actions
            assert "ACCOUNT_LOCKOUT" in rec_actions

    # Verify that the AI DID NOT directly execute any containment or alter firewall
    # In AegisSOC, recommendations require analyst approval through POST /actions/execute
    # Confirm incident is still OPEN, not resolved
    inc_stmt = select(Incident).where(Incident.id == incident.id)
    inc_res = await db_session.execute(inc_stmt)
    updated_inc = inc_res.scalar_one()
    assert updated_inc.status == "OPEN"
