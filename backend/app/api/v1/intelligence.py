"""REST API endpoints for Phase 5B Advanced Security Intelligence.

Endpoints:
- Security State Model (SecurityState(t), History, Transitions)
- Attack Trajectory
- Attack Graph
- Why Now Engine
- What Changed Engine
- Counterfactual Security Analysis
- Security Digital Twin & Blast Radius
- Organizational Security Memory
- Advanced Threat Intelligence (Hybrid)
- Continuous Security Improvement (Candidates & Approval)
- Continuous Adversary Scheduling
- MITRE Pipeline Coverage Tracker
- GRC Framework Intelligence
- Executive Security Posture Scorecard
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, get_tenant_context
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
    AttackGraphResponse,
    AttackTrajectoryResponse,
    BlastRadiusResponse,
    CandidateCreate,
    CandidateResponse,
    CounterfactualRequest,
    CounterfactualResponse,
    DigitalTwinResponse,
    ExecutivePostureReport,
    GrcFrameworkSummary,
    MemoryEntryCreate,
    MemoryEntryResponse,
    MitrePipelineCoverageReport,
    ScheduleCreate,
    ScheduleResponse,
    SecurityStateResponse,
    SecurityStateTransitionResponse,
    ThreatIntelLookupRequest,
    ThreatIntelLookupResponse,
    WhatChangedResponse,
    WhyNowResponse,
)
from app.intelligence.state_model import SecurityStateModel
from app.intelligence.threat_intelligence import ThreatIntelligenceService
from app.intelligence.what_changed import WhatChangedEngine
from app.intelligence.why_now import WhyNowEngine
from app.models.incident import Incident
from app.models.user import User
from app.security.tenant import TenantContext

router = APIRouter(prefix="/intelligence", tags=["Security Intelligence"])


# 5B-01: Dynamic Security State Model
@router.get("/state", response_model=SecurityStateResponse)
async def get_current_security_state(
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Computes and returns current dynamic SecurityState(t) for the tenant."""
    snap = await SecurityStateModel.compute_current_state(db=db, tenant_id=ctx.tenant_id)
    return snap


@router.get("/state/history", response_model=list[SecurityStateResponse])
async def get_security_state_history(
    limit: int = Query(20, ge=1, le=100),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves historical security state snapshots for the tenant."""
    return await SecurityStateModel.get_state_history(db=db, tenant_id=ctx.tenant_id, limit=limit)


@router.get("/state/transitions", response_model=list[SecurityStateTransitionResponse])
async def get_security_state_transitions(
    limit: int = Query(20, ge=1, le=100),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves auditable state transitions for the tenant."""
    return await SecurityStateModel.get_recent_transitions(db=db, tenant_id=ctx.tenant_id, limit=limit)


# 5B-02: Attack Trajectory
@router.get("/trajectory/{incident_id}", response_model=AttackTrajectoryResponse)
async def get_attack_trajectory(
    incident_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Evaluates multi-stage attack trajectory and probabilistic next stages for an incident."""
    return await AttackTrajectoryEngine.evaluate_incident_trajectory(
        db=db,
        tenant_id=ctx.tenant_id,
        incident_id=incident_id,
    )


# 5B-03: Attack Graph
@router.get("/graph", response_model=AttackGraphResponse)
async def get_attack_graph(
    incident_id: uuid.UUID | None = Query(None, description="Incident ID to generate attack graph for"),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Constructs tenant-isolated attack/evidence graph for an incident or latest tenant incident."""
    target_inc_id = incident_id
    if not target_inc_id:
        inc_stmt = select(Incident).where(Incident.tenant_id == ctx.tenant_id).order_by(Incident.created_at.desc())
        inc_res = await db.execute(inc_stmt)
        latest = inc_res.scalars().first()
        if latest:
            target_inc_id = latest.id

    if not target_inc_id:
        return AttackGraphResponse(
            tenant_id=ctx.tenant_id,
            nodes=[],
            edges=[],
            generated_at=datetime.now(UTC).isoformat(),
        )

    return await AttackGraphEngine.build_graph_for_incident(
        db=db,
        tenant_id=ctx.tenant_id,
        incident_id=target_inc_id,
    )


@router.get("/graph/paths", response_model=list[list[str]])
async def find_attack_paths(
    source_node_id: str = Query(..., description="Source node ID (e.g. ip:198.51.100.22)"),
    target_node_id: str = Query(..., description="Target node ID (e.g. host:lab-node-01)"),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Finds directed attack paths between source entity and target asset."""
    return await AttackGraphEngine.find_attack_paths(
        db=db,
        tenant_id=ctx.tenant_id,
        source_node_id=source_node_id,
        target_node_id=target_node_id,
    )


# 5B-04: Why Now Engine
@router.get("/why-now/{incident_id}", response_model=WhyNowResponse)
async def get_why_now_analysis(
    incident_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Explains why security state transitioned at the specific time of this incident."""
    return await WhyNowEngine.explain_incident(
        db=db,
        tenant_id=ctx.tenant_id,
        incident_id=incident_id,
    )


# 5B-05: What Changed Engine
@router.get("/what-changed/{entity_type}/{entity_id}", response_model=WhatChangedResponse)
async def get_what_changed_analysis(
    entity_type: str,
    entity_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Compares entity telemetry against historical baseline window."""
    return await WhatChangedEngine.compare_entity_baseline(
        db=db,
        tenant_id=ctx.tenant_id,
        entity_type=entity_type.upper(),
        entity_id=entity_id,
    )


# 5B-06: Counterfactual Security Analysis
@router.post("/counterfactual", response_model=CounterfactualResponse)
@router.post("/counterfactual/simulate", response_model=CounterfactualResponse)
async def simulate_counterfactual_action(
    request: CounterfactualRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Simulates security state trajectories under candidate containment actions (zero side-effects)."""
    return await CounterfactualAnalysisEngine.simulate_scenario(
        db=db,
        tenant_id=ctx.tenant_id,
        request=request,
    )


# 5B-07: Security Digital Twin
@router.get("/digital-twin", response_model=DigitalTwinResponse)
async def get_digital_twin_topology(
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves tenant digital twin asset topology and trust boundaries."""
    return await SecurityDigitalTwin.get_digital_twin(db=db, tenant_id=ctx.tenant_id)


@router.get("/digital-twin/blast-radius", response_model=BlastRadiusResponse)
async def calculate_blast_radius(
    seed_asset: str = Query(..., description="Hostname or IP address to compute blast radius for"),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Computes direct and transitive blast radius if seed asset is compromised."""
    return await SecurityDigitalTwin.calculate_blast_radius(
        db=db,
        tenant_id=ctx.tenant_id,
        seed_hostname_or_ip=seed_asset,
    )


# 5B-08: Organizational Security Memory
@router.post("/memory", response_model=MemoryEntryResponse, status_code=status.HTTP_201_CREATED)
async def create_memory_entry(
    payload: MemoryEntryCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Stores an evidence-linked organizational memory entry for the tenant."""
    return await OrganizationalMemoryService.record_memory(
        db=db,
        tenant_id=ctx.tenant_id,
        payload=payload,
        created_by=ctx.user_id,
    )


@router.get("/memory", response_model=list[MemoryEntryResponse])
async def query_memory_entries(
    category: str | None = Query(None),
    tag: str | None = Query(None),
    limit: int = Query(50, ge=1, le=100),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Queries tenant-isolated security memory entries."""
    return await OrganizationalMemoryService.query_memory(
        db=db,
        tenant_id=ctx.tenant_id,
        category=category,
        tag=tag,
        limit=limit,
    )


# 5B-09: Advanced Threat Intelligence
@router.post("/threat-intel/lookup", response_model=ThreatIntelLookupResponse)
async def lookup_threat_intelligence(
    request: ThreatIntelLookupRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Evaluates indicator reputation combined with actual tenant telemetry."""
    service = ThreatIntelligenceService()
    return await service.evaluate_indicator(
        db=db,
        tenant_id=ctx.tenant_id,
        request=request,
    )


# 5B-10: Continuous Security Improvement
@router.post(
    "/continuous-improvement/candidates", response_model=CandidateResponse, status_code=status.HTTP_201_CREATED
)
async def create_improvement_candidate(
    payload: CandidateCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Creates a candidate detection improvement rule recommendation."""
    return await ContinuousImprovementLoop.create_candidate(
        db=db,
        tenant_id=ctx.tenant_id,
        payload=payload,
    )


@router.get("/continuous-improvement/candidates", response_model=list[CandidateResponse])
async def list_improvement_candidates(
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Lists detection improvement candidates for tenant."""
    return await ContinuousImprovementLoop.list_candidates(
        db=db,
        tenant_id=ctx.tenant_id,
    )


@router.post("/continuous-improvement/candidates/{candidate_id}/review", response_model=CandidateResponse)
async def review_improvement_candidate(
    candidate_id: uuid.UUID,
    decision: str = Query(..., pattern="^(APPROVED|REJECTED)$"),
    user: User = Depends(get_current_user),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Applies human approval gate to candidate detection improvement."""
    return await ContinuousImprovementLoop.review_candidate(
        db=db,
        tenant_id=ctx.tenant_id,
        candidate_id=candidate_id,
        decision=decision,
        reviewer_id=user.id,
        reviewer_role=user.role,
        is_ai_agent=False,
    )


# 5B-11: Continuous Adversary Scheduling
@router.post("/adversary-schedule", response_model=ScheduleResponse, status_code=status.HTTP_201_CREATED)
async def schedule_adversary_assessment(
    payload: ScheduleCreate,
    user: User = Depends(get_current_user),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Registers recurring adversary validation schedule (LAB only, production rejected)."""
    return await ContinuousAdversaryScheduler.create_schedule(
        db=db,
        tenant_id=ctx.tenant_id,
        payload=payload,
        creator_id=user.id,
        creator_role=user.role,
    )


@router.get("/adversary-schedule", response_model=list[ScheduleResponse])
async def list_adversary_schedules(
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Lists adversary validation schedules for tenant."""
    return await ContinuousAdversaryScheduler.list_schedules(
        db=db,
        tenant_id=ctx.tenant_id,
    )


# 5B-12: MITRE Pipeline Coverage
@router.get("/mitre-matrix", response_model=MitrePipelineCoverageReport)
async def get_mitre_pipeline_coverage(
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Returns end-to-end MITRE ATT&CK pipeline coverage report."""
    return await MitreCoverageTracker.generate_pipeline_report(
        db=db,
        tenant_id=ctx.tenant_id,
    )


# 5B-13: GRC Intelligence
@router.get("/grc", response_model=GrcFrameworkSummary)
async def get_grc_compliance_summary(
    framework: str = Query(
        "NIST_CSF", description="Framework name (NIST_CSF, ISO_27001, CIS_CONTROLS, SOC_2, PCI_DSS)"
    ),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Returns auditable compliance report for specified GRC framework."""
    return await GrcIntelligenceEngine.get_framework_summary(
        db=db,
        tenant_id=ctx.tenant_id,
        framework=framework,
    )


# 5B-14: Executive Security Posture
@router.get("/executive-posture", response_model=ExecutivePostureReport)
@router.get("/posture/executive", response_model=ExecutivePostureReport)
async def get_executive_security_posture(
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Generates tenant executive security posture report across 9 domains."""
    return await ExecutivePostureEngine.generate_executive_posture(
        db=db,
        tenant_id=ctx.tenant_id,
    )
