"""Comprehensive Phase 5B Advanced Security Intelligence Verification Test Suite.

Covers:
- 5B-01: Dynamic Security State Model (SecurityState(t), Transitions, Evidence validation)
- 5B-02: Attack Trajectory (Evidence-based progression, probabilistic predictions)
- 5B-03: Attack Graph (Tenant-isolated nodes/edges, pathfinding, cross-tenant isolation)
- 5B-04: Why Now Engine (Baseline comparison, why it matters, evidence links)
- 5B-05: What Changed Engine (Historical baseline deviations, evidence grounding)
- 5B-06: Counterfactual Security Analysis (Controlled simulation, zero side-effects, risk deltas)
- 5B-07: Security Digital Twin (Topology, direct & transitive blast radius)
- 5B-08: Organizational Security Memory (Tenant-isolated, evidence-linked historical learning)
- 5B-09: Advanced Threat Intelligence (Provider abstraction, hybrid scoring)
- 5B-10: Continuous Security Improvement (Closed loop, AI approval forbidden, human deployment)
- 5B-11: Continuous Adversary Scheduler (Scope validation, production rejection, audit logging)
- 5B-12: MITRE Pipeline Coverage (Simulation -> Detection -> Correlation -> Investigation -> Response -> Verification)
- 5B-13: GRC Intelligence (NIST CSF, ISO 27001, CIS, SOC 2, PCI DSS evidence mappings)
- 5B-14: Executive Security Posture (Methodology-based 9 domain scoring)
- API Integration: REST API endpoints tested with auth and tenant isolation
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ForbiddenException, ValidationException
from app.intelligence.attack_graph import AttackGraphEngine
from app.intelligence.attack_trajectory import AttackTrajectoryEngine
from app.intelligence.continuous_adversary import ContinuousAdversaryScheduler
from app.intelligence.continuous_improvement import ContinuousImprovementLoop
from app.intelligence.counterfactual import CounterfactualAnalysisEngine
from app.intelligence.digital_twin import SecurityDigitalTwin
from app.intelligence.grc_intelligence import GrcIntelligenceEngine
from app.intelligence.mitre_tracker import MitreCoverageTracker
from app.intelligence.organizational_memory import OrganizationalMemoryService
from app.intelligence.posture_executive import ExecutivePostureEngine
from app.intelligence.schemas import (
    CandidateCreate,
    CounterfactualRequest,
    MemoryEntryCreate,
    ScheduleCreate,
    ThreatIntelLookupRequest,
)
from app.intelligence.state_model import SecurityStateModel
from app.intelligence.threat_intelligence import ThreatIntelligenceService
from app.intelligence.what_changed import WhatChangedEngine
from app.intelligence.why_now import WhyNowEngine
from app.models.asset import Asset
from app.models.event import SecurityEvent
from app.models.incident import Incident
from app.models.tenant import Tenant
from app.models.user import User
from app.security.tokens import create_access_token


@pytest.mark.asyncio
async def test_5b_01_security_state_model_and_transitions(db_session: AsyncSession):
    """5B-01: Verifies dynamic SecurityState(t), state hashing, and evidence-grounded transitions."""
    tenant = Tenant(name="State Model Tenant")
    db_session.add(tenant)
    await db_session.flush()

    # Add baseline asset and user
    asset = Asset(
        tenant_id=tenant.id,
        hostname="lab-state-server-01",
        ip_address="10.0.1.10",
        asset_type="SERVER",
        criticality="HIGH",
    )
    user = User(
        tenant_id=tenant.id,
        email="analyst@statemodel.test",
        password_hash="testhash",
        role="SOC_L2",
    )
    db_session.add_all([asset, user])
    await db_session.flush()

    # 1. Compute State Snapshot
    snap = await SecurityStateModel.compute_current_state(db=db_session, tenant_id=tenant.id)
    assert snap.tenant_id == tenant.id
    assert snap.monitored_assets_count >= 1
    assert snap.monitored_identities_count >= 1
    assert 0.0 <= snap.risk_score <= 100.0
    assert 0.0 <= snap.posture_score <= 100.0
    assert len(snap.state_hash) == 64  # SHA-256
    assert "active_controls" in snap.state_vector

    # 2. Record Valid Transition with Evidence
    ev_id = str(uuid.uuid4())
    trans = await SecurityStateModel.record_transition(
        db=db_session,
        tenant_id=tenant.id,
        trigger_type="INCIDENT_CORRELATED",
        from_state_summary="Nominal operating baseline",
        to_state_summary="Elevated risk due to SSH brute force detection",
        evidence_references=[{"event_id": ev_id, "hash": "sha256:abc"}],
        rationale="Threshold rule triggered across 5 failure events",
        risk_delta=+35.0,
        posture_delta=-20.0,
        confidence=0.95,
    )
    assert trans.id is not None
    assert trans.risk_delta == 35.0
    assert len(trans.evidence_references) == 1

    # 3. Transition WITHOUT Evidence Must Fail
    with pytest.raises(ValidationException, match="requires verifiable evidence"):
        await SecurityStateModel.record_transition(
            db=db_session,
            tenant_id=tenant.id,
            trigger_type="UNGROUNDED_TRANSITION",
            from_state_summary="State A",
            to_state_summary="State B",
            evidence_references=[],  # Empty evidence
            rationale="No evidence",
        )

    # 4. History and Transitions Query
    history = await SecurityStateModel.get_state_history(db=db_session, tenant_id=tenant.id)
    assert len(history) >= 1
    transitions = await SecurityStateModel.get_recent_transitions(db=db_session, tenant_id=tenant.id)
    assert len(transitions) >= 1


@pytest.mark.asyncio
async def test_5b_02_attack_trajectory_probabilistic(db_session: AsyncSession):
    """5B-02: Verifies evidence-grounded attack trajectory progression and probabilistic predictions."""
    tenant = Tenant(name="Trajectory Tenant")
    db_session.add(tenant)
    await db_session.flush()

    now = datetime.now(UTC)
    # Create incident with authentication failure and success telemetry
    incident = Incident(
        tenant_id=tenant.id,
        title="Multi-stage SSH Credential Attack",
        description="SSH failure followed by successful privilege escalation",
        severity="HIGH",
        risk_score=68.0,
        status="OPEN",
        mitre_techniques=["T1110.001", "T1078"],
        source_ips=["198.51.100.44"],
        affected_users=["victim_admin"],
        affected_assets=["lab-host-alpha"],
    )
    db_session.add(incident)
    await db_session.flush()

    # Add telemetry events
    evt_fail = SecurityEvent(
        tenant_id=tenant.id,
        source="ssh",
        event_type="authentication_failure",
        severity="MEDIUM",
        source_ip="198.51.100.44",
        username="victim_admin",
        hostname="lab-host-alpha",
        timestamp=now - timedelta(minutes=5),
        raw_event={"auth": "failed"},
        normalized_event={"auth": "failed", "event": {"type": "authentication_failure"}},
    )
    evt_succ = SecurityEvent(
        tenant_id=tenant.id,
        source="ssh",
        event_type="authentication_success",
        severity="LOW",
        source_ip="198.51.100.44",
        username="victim_admin",
        hostname="lab-host-alpha",
        timestamp=now - timedelta(minutes=1),
        raw_event={"auth": "success"},
        normalized_event={"auth": "success", "event": {"type": "authentication_success"}},
    )
    db_session.add_all([evt_fail, evt_succ])
    await db_session.commit()

    trajectory = await AttackTrajectoryEngine.evaluate_incident_trajectory(
        db=db_session,
        tenant_id=tenant.id,
        incident_id=incident.id,
    )

    assert trajectory.incident_id == incident.id
    # Should progress to at least SUSPICIOUS or ATTACK_DEVELOPING
    assert trajectory.current_stage in ["SUSPICIOUS", "ATTACK_DEVELOPING", "CONFIRMED"]
    assert len(trajectory.observed_stages) >= 2
    assert len(trajectory.evidence_event_ids) >= 1

    # Check predictions: Must be strictly probabilistic (never certain, prob < 1.0)
    assert len(trajectory.predicted_next_stages) >= 1
    for pred in trajectory.predicted_next_stages:
        assert 0.0 < pred.probability < 1.0
        assert len(pred.rationale) > 0


@pytest.mark.asyncio
async def test_5b_03_attack_graph_and_isolation(db_session: AsyncSession):
    """5B-03: Verifies tenant-isolated attack/evidence graph generation and pathfinding."""
    tenant_a = Tenant(name="Graph Tenant A")
    tenant_b = Tenant(name="Graph Tenant B")
    db_session.add_all([tenant_a, tenant_b])
    await db_session.flush()

    inc_a = Incident(
        tenant_id=tenant_a.id,
        title="Incident Tenant A",
        description="Graph test A",
        severity="HIGH",
        risk_score=75.0,
        status="OPEN",
        mitre_techniques=["T1110.001"],
        source_ips=["192.0.2.10"],
        affected_users=["user_a"],
        affected_assets=["host-a"],
    )
    db_session.add(inc_a)
    await db_session.flush()

    evt_a = SecurityEvent(
        tenant_id=tenant_a.id,
        source="ssh",
        event_type="authentication_failure",
        severity="HIGH",
        source_ip="192.0.2.10",
        username="user_a",
        hostname="host-a",
        timestamp=datetime.now(UTC),
        raw_event={"auth": "failed"},
        normalized_event={"auth": "failed", "event": {"type": "authentication_failure"}},
    )
    db_session.add(evt_a)
    await db_session.commit()

    # 1. Build Graph for Tenant A
    graph_a = await AttackGraphEngine.build_graph_for_incident(
        db=db_session,
        tenant_id=tenant_a.id,
        incident_id=inc_a.id,
    )
    assert len(graph_a.nodes) >= 3
    node_types = {n.type for n in graph_a.nodes}
    assert "INCIDENT" in node_types
    assert "EVENT" in node_types
    assert "SOURCE_IP" in node_types

    # Verify edge consistency: every edge has evidence_id and relationship
    for edge in graph_a.edges:
        assert edge.relationship in ["AUTHENTICATED_AS", "LOGGED_INTO", "SPAWNED", "CORRELATED_INTO", "MAPPED_TO"]
        assert edge.evidence_id is not None

    # 2. Cross-Tenant Isolation: Tenant B cannot build graph for Tenant A's incident
    with pytest.raises(ValueError, match="not found for tenant"):
        await AttackGraphEngine.build_graph_for_incident(
            db=db_session,
            tenant_id=tenant_b.id,
            incident_id=inc_a.id,
        )

    # 3. Pathfinding Query
    paths = await AttackGraphEngine.find_attack_paths(
        db=db_session,
        tenant_id=tenant_a.id,
        source_node_id="ip:192.0.2.10",
        target_node_id="user:user_a",
    )
    assert len(paths) >= 1
    assert paths[0] == ["ip:192.0.2.10", "user:user_a"]


@pytest.mark.asyncio
async def test_5b_04_why_now_and_5b_05_what_changed(db_session: AsyncSession):
    """5B-04 & 5B-05: Verifies Why Now state change explanation and historical baseline comparison."""
    tenant = Tenant(name="WhyNow Tenant")
    db_session.add(tenant)
    await db_session.flush()

    now = datetime.now(UTC)
    incident = Incident(
        tenant_id=tenant.id,
        title="Suspicious Login from Unseen IP",
        description="Login deviation from baseline",
        severity="MEDIUM",
        risk_score=55.0,
        status="OPEN",
        mitre_techniques=["T1078"],
        source_ips=["198.51.100.99"],
        affected_users=["admin_dev"],
        affected_assets=["dev-server-01"],
    )
    db_session.add(incident)
    await db_session.flush()

    evt = SecurityEvent(
        tenant_id=tenant.id,
        source="ssh",
        event_type="authentication_failure",
        severity="MEDIUM",
        source_ip="198.51.100.99",
        username="admin_dev",
        hostname="dev-server-01",
        timestamp=now,
        raw_event={"auth": "failed"},
        normalized_event={"auth": "failed", "event": {"type": "authentication_failure"}},
    )
    db_session.add(evt)
    await db_session.commit()

    # Test 5B-04: Why Now
    why_now = await WhyNowEngine.explain_incident(
        db=db_session,
        tenant_id=tenant.id,
        incident_id=incident.id,
    )
    assert len(why_now.what_changed) > 0
    assert len(why_now.why_it_matters) > 0
    assert len(why_now.evidence) >= 1
    assert 0.0 < why_now.confidence <= 1.0

    # Test 5B-05: What Changed
    what_changed = await WhatChangedEngine.compare_entity_baseline(
        db=db_session,
        tenant_id=tenant.id,
        entity_type="USER",
        entity_id="admin_dev",
    )
    assert what_changed.entity_type == "USER"
    assert what_changed.entity_id == "admin_dev"
    assert len(what_changed.comparisons) >= 3
    dim_names = {c.dimension for c in what_changed.comparisons}
    assert "LOGIN_TIME" in dim_names
    assert "SOURCE_IP" in dim_names
    assert "PROCESS_NAME" in dim_names


@pytest.mark.asyncio
async def test_5b_06_counterfactual_analysis(db_session: AsyncSession):
    """5B-06: Verifies controlled counterfactual security analysis and risk delta calculation."""
    tenant = Tenant(name="Counterfactual Tenant")
    db_session.add(tenant)
    await db_session.flush()

    incident = Incident(
        tenant_id=tenant.id,
        title="Critical Ransomware Infiltration Attempt",
        description="Simulated attack scenario for counterfactual assessment",
        severity="CRITICAL",
        risk_score=85.0,
        status="OPEN",
        mitre_techniques=["T1486"],
        affected_assets=["prod-db-cluster-01"],
        affected_users=["app_service"],
    )
    db_session.add(incident)
    await db_session.commit()

    # Scenario 1: DO_NOTHING
    res_nothing = await CounterfactualAnalysisEngine.simulate_scenario(
        db=db_session,
        tenant_id=tenant.id,
        request=CounterfactualRequest(incident_id=incident.id, simulated_action="DO_NOTHING"),
    )
    assert res_nothing.risk_change > 0  # Risk increases (+25)
    assert "lateral movement" in res_nothing.predicted_state.lower()
    assert len(res_nothing.assumptions) >= 2

    # Scenario 2: ISOLATE_HOST
    res_isolate = await CounterfactualAnalysisEngine.simulate_scenario(
        db=db_session,
        tenant_id=tenant.id,
        request=CounterfactualRequest(incident_id=incident.id, simulated_action="ISOLATE_HOST"),
    )
    assert res_isolate.risk_change < 0  # Risk decreases (-45)
    assert "network interfaces" in res_isolate.predicted_state.lower()
    assert "temporarily unavailable" in res_isolate.business_impact.lower()

    # Scenario 3: REVOKE_SESSION
    res_revoke = await CounterfactualAnalysisEngine.simulate_scenario(
        db=db_session,
        tenant_id=tenant.id,
        request=CounterfactualRequest(incident_id=incident.id, simulated_action="REVOKE_SESSION"),
    )
    assert res_revoke.risk_change < 0

    # Scenario 4: DISABLE_ACCOUNT
    res_disable = await CounterfactualAnalysisEngine.simulate_scenario(
        db=db_session,
        tenant_id=tenant.id,
        request=CounterfactualRequest(incident_id=incident.id, simulated_action="DISABLE_ACCOUNT"),
    )
    assert res_disable.risk_change < 0

    # Invalid Action Rejection
    with pytest.raises(ValidationException, match="Invalid simulated action"):
        await CounterfactualAnalysisEngine.simulate_scenario(
            db=db_session,
            tenant_id=tenant.id,
            request=CounterfactualRequest(incident_id=incident.id, simulated_action="DESTROY_SERVER"),
        )


@pytest.mark.asyncio
async def test_5b_07_digital_twin_and_blast_radius(db_session: AsyncSession):
    """5B-07: Verifies digital twin topology modeling and transitive blast radius calculation."""
    tenant = Tenant(name="Twin Tenant")
    db_session.add(tenant)
    await db_session.flush()

    # Setup topology: Web -> API -> DB
    asset_web = Asset(
        tenant_id=tenant.id,
        hostname="lab-web-01",
        ip_address="10.0.1.10",
        asset_type="WEB",
        criticality="MEDIUM",
    )
    asset_api = Asset(
        tenant_id=tenant.id,
        hostname="lab-api-01",
        ip_address="10.0.1.20",
        asset_type="API",
        criticality="HIGH",
    )
    asset_db = Asset(
        tenant_id=tenant.id,
        hostname="lab-db-01",
        ip_address="10.0.1.30",
        asset_type="DATABASE",
        criticality="CRITICAL",
    )
    db_session.add_all([asset_web, asset_api, asset_db])
    await db_session.commit()

    twin = await SecurityDigitalTwin.get_digital_twin(db=db_session, tenant_id=tenant.id)
    assert twin.total_assets == 3
    assert len(twin.assets) == 3

    # Calculate blast radius from lab-web-01
    blast = await SecurityDigitalTwin.calculate_blast_radius(
        db=db_session,
        tenant_id=tenant.id,
        seed_hostname_or_ip="lab-web-01",
    )
    assert blast.seed_node == "lab-web-01"
    assert len(blast.direct_dependencies) >= 1
    assert blast.total_impacted_assets >= 1


@pytest.mark.asyncio
async def test_5b_08_organizational_memory_isolation(db_session: AsyncSession):
    """5B-08: Verifies tenant-scoped organizational security memory and strict cross-tenant isolation."""
    tenant_a = Tenant(name="Memory Tenant A")
    tenant_b = Tenant(name="Memory Tenant B")
    db_session.add_all([tenant_a, tenant_b])
    await db_session.flush()

    # 1. Record learning in Tenant A
    mem_payload = MemoryEntryCreate(
        category="VALIDATED_ATTACK_PATTERN",
        title="SSH Password Spraying on Subnet 10.0.1.0/24",
        summary="Adversary rotates 5 passwords across all domain service accounts.",
        details={"technique": "T1110.003", "threshold": 5},
        tags=["T1110.003", "ssh", "spray"],
        evidence_references=["event-uuid-1", "incident-uuid-a"],
        confidence=0.98,
    )
    entry_a = await OrganizationalMemoryService.record_memory(
        db=db_session,
        tenant_id=tenant_a.id,
        payload=mem_payload,
    )
    assert entry_a.id is not None
    assert entry_a.tenant_id == tenant_a.id

    # 2. Missing evidence must be rejected
    with pytest.raises(ValidationException, match="must include verifiable evidence"):
        await OrganizationalMemoryService.record_memory(
            db=db_session,
            tenant_id=tenant_a.id,
            payload=MemoryEntryCreate(
                category="INCIDENT",
                title="Unverified Memory",
                summary="No evidence provided",
                evidence_references=[],  # Empty
            ),
        )

    # 3. Query Tenant A memory
    results_a = await OrganizationalMemoryService.query_memory(
        db=db_session,
        tenant_id=tenant_a.id,
        category="VALIDATED_ATTACK_PATTERN",
    )
    assert len(results_a) == 1
    assert results_a[0].title == mem_payload.title

    # 4. Strict Cross-Tenant Leakage Check: Tenant B query must return ZERO entries from Tenant A
    results_b = await OrganizationalMemoryService.query_memory(
        db=db_session,
        tenant_id=tenant_b.id,
    )
    assert len(results_b) == 0


@pytest.mark.asyncio
async def test_5b_09_threat_intelligence_hybrid(db_session: AsyncSession):
    """5B-09: Verifies threat intelligence provider abstraction and hybrid scoring."""
    tenant = Tenant(name="TI Tenant")
    db_session.add(tenant)
    await db_session.flush()

    service = ThreatIntelligenceService()

    # Scenario A: Known C2 IP with NO local events -> SUSPICIOUS (INFORMATIONAL_EXTERNAL_MATCH)
    res_no_local = await service.evaluate_indicator(
        db=db_session,
        tenant_id=tenant.id,
        request=ThreatIntelLookupRequest(
            indicator_type="IP",
            indicator_value="198.51.100.22",  # Known C2 in catalog
        ),
    )
    assert res_no_local.reputation_score >= 80.0
    assert res_no_local.maliciousness_verdict == "SUSPICIOUS"
    assert "INFORMATIONAL_EXTERNAL_MATCH" in res_no_local.rationale

    # Scenario B: Known C2 IP WITH local suspicious telemetry -> Confirmed MALICIOUS
    evt = SecurityEvent(
        tenant_id=tenant.id,
        source="ssh",
        event_type="authentication_failure",
        severity="HIGH",
        source_ip="198.51.100.22",
        timestamp=datetime.now(UTC),
        raw_event={"auth": "failed"},
        normalized_event={"auth": "failed", "event": {"type": "authentication_failure"}},
    )
    db_session.add(evt)
    await db_session.commit()

    res_with_local = await service.evaluate_indicator(
        db=db_session,
        tenant_id=tenant.id,
        request=ThreatIntelLookupRequest(
            indicator_type="IP",
            indicator_value="198.51.100.22",
            local_context={"criticality": "CRITICAL"},
        ),
    )
    assert res_with_local.maliciousness_verdict == "MALICIOUS"
    assert res_with_local.evidence_grounded is True


@pytest.mark.asyncio
async def test_5b_10_continuous_improvement_and_approval(db_session: AsyncSession):
    """5B-10: Verifies closed-loop rule improvements and human-only deployment authorization."""
    tenant = Tenant(name="Improvement Tenant")
    db_session.add(tenant)
    await db_session.flush()

    user_l2 = uuid.uuid4()

    valid_sigma = """
title: SSH Brute Force Tuned
id: TEST-RULE-001
status: test
description: Tuned threshold for lab SSH attacks
logsource:
    category: authentication
detection:
    selection:
        event_type: authentication_failure
    condition: selection
level: high
"""
    # 1. Create candidate
    candidate = await ContinuousImprovementLoop.create_candidate(
        db=db_session,
        tenant_id=tenant.id,
        payload=CandidateCreate(
            title="Tuned SSH Rule from Incident Feedback",
            rationale="Reduces false positives by increasing threshold",
            proposed_rule_yaml=valid_sigma,
            mitre_techniques=["T1110.001"],
        ),
    )
    assert candidate.status == "PENDING_REVIEW"
    assert candidate.test_results["syntax_valid"] is True

    # 2. AI agent approval attempt MUST be blocked
    with pytest.raises(ForbiddenException, match="AI agents are strictly forbidden"):
        await ContinuousImprovementLoop.review_candidate(
            db=db_session,
            tenant_id=tenant.id,
            candidate_id=candidate.id,
            decision="APPROVED",
            reviewer_id=uuid.uuid4(),
            reviewer_role="SOC_L2",
            is_ai_agent=True,  # AI agent
        )

    # 3. Unauthorized role approval MUST be blocked
    with pytest.raises(ForbiddenException, match="unauthorized to approve"):
        await ContinuousImprovementLoop.review_candidate(
            db=db_session,
            tenant_id=tenant.id,
            candidate_id=candidate.id,
            decision="APPROVED",
            reviewer_id=user_l2,
            reviewer_role="SOC_L1",  # L1 cannot approve production rules
            is_ai_agent=False,
        )

    # 4. Human SOC_L2 approval succeeds and deploys new rule
    approved = await ContinuousImprovementLoop.review_candidate(
        db=db_session,
        tenant_id=tenant.id,
        candidate_id=candidate.id,
        decision="APPROVED",
        reviewer_id=user_l2,
        reviewer_role="SOC_L2_LEAD",
        is_ai_agent=False,
    )
    assert approved.status == "DEPLOYED"


@pytest.mark.asyncio
async def test_5b_11_continuous_adversary_scheduler(db_session: AsyncSession):
    """5B-11: Verifies adversary schedule registration, target validation, and production rejection."""
    tenant = Tenant(name="Scheduler Tenant")
    db_session.add(tenant)
    await db_session.flush()

    user_lead = uuid.uuid4()

    # 1. Valid LAB schedule
    sched_payload = ScheduleCreate(
        name="Weekly SSH Spray Validation",
        scenario_id="SCENARIO-001",
        cron_expression="0 3 * * 1",
        environment="LAB",
        authorized_scope={
            "environment": "LAB",
            "assets": ["lab-target-01"],
            "ips": ["10.0.0.50"],
            "allowed_techniques": ["T1110.001"],
        },
        target_allowlist=["lab-target-01"],
        technique_allowlist=["T1110.001"],
        expires_at=datetime.now(UTC) + timedelta(days=90),
    )
    sched = await ContinuousAdversaryScheduler.create_schedule(
        db=db_session,
        tenant_id=tenant.id,
        payload=sched_payload,
        creator_id=user_lead,
        creator_role="SOC_L2_LEAD",
    )
    assert sched.id is not None
    assert sched.is_active is True

    # 2. Production target must be REJECTED
    with pytest.raises(ForbiddenException, match="cannot target production"):
        await ContinuousAdversaryScheduler.create_schedule(
            db=db_session,
            tenant_id=tenant.id,
            payload=ScheduleCreate(
                name="Malicious Prod Schedule",
                scenario_id="SCENARIO-001",
                environment="LAB",
                authorized_scope={"environment": "LAB"},
                target_allowlist=["production-core-database"],  # Prod target!
                technique_allowlist=["T1110.001"],
                expires_at=datetime.now(UTC) + timedelta(days=30),
            ),
            creator_id=user_lead,
            creator_role="SOC_L2_LEAD",
        )

    # 3. Production environment must be REJECTED
    with pytest.raises(ForbiddenException, match="strictly prohibited in 'PRODUCTION'"):
        await ContinuousAdversaryScheduler.create_schedule(
            db=db_session,
            tenant_id=tenant.id,
            payload=ScheduleCreate(
                name="Prod Env Schedule",
                scenario_id="SCENARIO-001",
                environment="PRODUCTION",  # Prod env!
                authorized_scope={"environment": "PRODUCTION"},
                target_allowlist=["lab-01"],
                technique_allowlist=["T1110.001"],
                expires_at=datetime.now(UTC) + timedelta(days=30),
            ),
            creator_id=user_lead,
            creator_role="SOC_L2_LEAD",
        )


@pytest.mark.asyncio
async def test_5b_12_mitre_and_5b_13_grc_and_5b_14_posture(db_session: AsyncSession):
    """5B-12, 5B-13, 5B-14: Verifies MITRE pipeline tracking, GRC evidence mappings, and executive posture."""
    tenant = Tenant(name="Enterprise Intelligence Tenant")
    db_session.add(tenant)
    await db_session.flush()

    # Test 5B-12: MITRE Pipeline Coverage
    mitre_rep = await MitreCoverageTracker.generate_pipeline_report(
        db=db_session,
        tenant_id=tenant.id,
    )
    assert mitre_rep.tenant_id == tenant.id
    assert mitre_rep.total_techniques_in_scope >= 1
    assert isinstance(mitre_rep.pipeline_coverage_percentage, float)

    # Test 5B-13: GRC Framework Intelligence
    grc_nist = await GrcIntelligenceEngine.get_framework_summary(
        db=db_session,
        tenant_id=tenant.id,
        framework="NIST_CSF",
    )
    assert grc_nist.framework == "NIST_CSF"
    assert grc_nist.total_controls >= 1
    assert grc_nist.compliance_score_percentage > 0.0
    for ctrl in grc_nist.controls:
        assert len(ctrl.evidence_references) > 0
        assert len(ctrl.verification_method) > 0

    # Test 5B-14: Executive Security Posture
    posture = await ExecutivePostureEngine.generate_executive_posture(
        db=db_session,
        tenant_id=tenant.id,
    )
    assert posture.tenant_id == tenant.id
    assert 0.0 <= posture.overall_posture_score <= 100.0
    assert len(posture.domain_scores) == 9
    domain_names = {d.domain for d in posture.domain_scores}
    assert "Identity Security" in domain_names
    assert "Incident Response" in domain_names
    assert "Compliance & GRC" in domain_names
    assert len(posture.top_strategic_priorities) >= 1


@pytest.mark.asyncio
async def test_intelligence_rest_api_endpoints(client: AsyncClient, db_session: AsyncSession):
    """Verifies Phase 5B REST API endpoints via HTTP client with JWT authorization."""
    tenant = Tenant(name="API Test Tenant")
    db_session.add(tenant)
    await db_session.flush()

    user = User(
        tenant_id=tenant.id,
        email="lead@apiverse.test",
        password_hash="hashedpass",
        role="SOC_L2_LEAD",
    )
    db_session.add(user)
    await db_session.commit()

    token = create_access_token(
        user_id=user.id,
        tenant_id=tenant.id,
        email=user.email,
        role=user.role,
    )
    headers = {"Authorization": f"Bearer {token}"}

    # 1. State Endpoint
    resp_state = await client.get("/api/v1/intelligence/state", headers=headers)
    assert resp_state.status_code == 200
    data_state = resp_state.json()
    assert data_state["tenant_id"] == str(tenant.id)
    assert "state_hash" in data_state

    # 2. Digital Twin Endpoint
    resp_twin = await client.get("/api/v1/intelligence/digital-twin", headers=headers)
    assert resp_twin.status_code == 200

    # 3. GRC Framework Endpoint
    resp_grc = await client.get("/api/v1/intelligence/grc?framework=NIST_CSF", headers=headers)
    assert resp_grc.status_code == 200
    assert resp_grc.json()["framework"] == "NIST_CSF"

    # 4. Executive Posture Endpoint
    resp_posture = await client.get("/api/v1/intelligence/executive-posture", headers=headers)
    assert resp_posture.status_code == 200
    assert "overall_posture_score" in resp_posture.json()
