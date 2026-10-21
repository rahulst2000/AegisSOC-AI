import time
import tracemalloc
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.adversary.executor import execute_adversary_assessment
from app.adversary.models import AdversaryAssessment
from app.detection.engine import DetectionEngine
from app.models.event import SecurityEvent
from app.models.incident import Incident
from app.models.tenant import Tenant
from app.security_improvement.gap_engine import GapEngine
from app.security_improvement.models import SecurityFinding
from app.security_improvement.remediation import RemediationEngine
from app.security_improvement.retest import RetestEngine
from app.security_improvement.schemas import RemediationActionCreate


@pytest.mark.asyncio
async def test_benchmark_phase4_performance(db_session: AsyncSession):
    """
    Phase 4 Performance Benchmark:
    - 10,000 telemetry events
    - 100 incidents
    - 100 adversary validation records
    - 1,000 security findings
    Measures actual:
    - Assessment creation latency
    - Simulation orchestration latency
    - Detection latency
    - Gap analysis latency
    - Remediation tracking latency
    - Retest latency
    - Memory usage
    """
    tracemalloc.start()
    t_global_start = time.perf_counter()

    tenant = Tenant(name="Benchmark Phase 4 Tenant")
    db_session.add(tenant)
    await db_session.flush()

    user_id = uuid.uuid4()
    base_time = datetime.now(UTC)

    # 1. Ingest 10,000 Telemetry Events in bulk
    events: list[SecurityEvent] = []
    for i in range(10000):
        evt = SecurityEvent(
            tenant_id=tenant.id,
            source="benchmark_ssh",
            event_type="authentication_failure" if i % 3 != 0 else "authentication_success",
            severity="MEDIUM" if i % 3 != 0 else "LOW",
            source_ip=f"10.10.1.{1 + (i % 200)}",
            username=f"lab_user_{i % 100}",
            hostname=f"lab-node-{(i % 20):02d}",
            timestamp=base_time + timedelta(seconds=i),
            raw_event={"auth": {"result": "failure" if i % 3 != 0 else "success"}},
            normalized_event={"event": {"type": "authentication_failure" if i % 3 != 0 else "authentication_success"}},
        )
        events.append(evt)

    db_session.add_all(events)
    await db_session.flush()

    # 2. Ingest 100 Correlated Incidents
    incidents: list[Incident] = []
    for i in range(100):
        inc = Incident(
            tenant_id=tenant.id,
            title=f"Incident {i}: Simulated Attack Pattern",
            description=f"Automated incident {i} for benchmark",
            severity="HIGH" if i % 2 == 0 else "MEDIUM",
            risk_score=75,
            confidence=0.92,
            status="OPEN" if i < 80 else "CLOSED",
            source_ips=[f"10.10.1.{1 + i}"],
            created_at=base_time + timedelta(minutes=i),
        )
        incidents.append(inc)

    db_session.add_all(incidents)
    await db_session.flush()

    # 3. Create 100 Adversary Validation Records & Measure Assessment Creation Latency
    assessments: list[AdversaryAssessment] = []
    t_create_start = time.perf_counter()
    for i in range(100):
        scope = {
            "environment": "LAB",
            "assets": [f"lab-node-{(i % 20):02d}"],
            "ips": [f"10.10.1.{1 + i}"],
            "allowed_techniques": ["T1110.001", "T1110.003", "T1078", "T1078.003"],
            "prohibited_techniques": ["persistence", "data_exfiltration"],
            "expires_at": (base_time + timedelta(hours=4)).isoformat(),
            "authorized_by": str(user_id),
        }
        assessment = AdversaryAssessment(
            tenant_id=tenant.id,
            name=f"Validation Assessment {i:03d}",
            environment="LAB",
            scenario="SCENARIO-001" if i % 2 == 0 else "SCENARIO-002",
            status="AUTHORIZED",
            authorized_scope=scope,
            created_by=user_id,
            authorized_by=user_id,
        )
        assessments.append(assessment)

    db_session.add_all(assessments)
    await db_session.flush()
    create_latency = (time.perf_counter() - t_create_start) / 100.0

    # 4. Ingest 1,000 Security Findings
    findings: list[SecurityFinding] = []
    for i in range(1000):
        f = SecurityFinding(
            tenant_id=tenant.id,
            assessment_id=assessments[i % 100].id,
            severity="HIGH" if i % 4 == 0 else "MEDIUM",
            title=f"Finding {i}: Detection Gap in Subnet {i % 10}",
            description=f"Benchmark finding {i} description",
            asset=f"lab-node-{(i % 20):02d}",
            technique="T1110.001" if i % 2 == 0 else "T1110.003",
            root_cause="Missing host telemetry",
            business_impact="SOC blind spot",
            recommendation="Deploy threshold rule",
            priority="P1" if i % 4 == 0 else "P2",
            owner="Security Engineering",
            status="OPEN" if i < 700 else "UNDER_REMEDIATION",
            created_at=base_time + timedelta(minutes=i),
        )
        findings.append(f)

    db_session.add_all(findings)
    await db_session.flush()

    # 5. Measure Detection Latency over sample events
    sample_events = events[:10]
    engine = DetectionEngine()
    t_det_start = time.perf_counter()
    _ = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=sample_events)
    detection_latency = time.perf_counter() - t_det_start

    # 6. Measure Simulation Orchestration Latency
    test_assessment = assessments[0]
    t_sim_start = time.perf_counter()
    sim_result = await execute_adversary_assessment(
        db=db_session,
        tenant_id=tenant.id,
        assessment_id=test_assessment.id,
        user_id=user_id,
        user_role="SOC_L2",
    )
    simulation_latency = time.perf_counter() - t_sim_start

    # 7. Measure Gap Analysis Latency
    t_gap_start = time.perf_counter()
    gaps = GapEngine.analyze_result(sim_result)
    gap_latency = time.perf_counter() - t_gap_start

    # 8. Measure Remediation Tracking Latency
    target_finding = findings[0]
    rem_payload = RemediationActionCreate(
        proposed_change="Update rule threshold from 10 to 5",
        change_type="RULE_UPDATE",
    )
    t_rem_start = time.perf_counter()
    rem = await RemediationEngine.create_remediation(
        db=db_session,
        tenant_id=tenant.id,
        finding_id=target_finding.id,
        payload=rem_payload,
    )
    approved_rem = await RemediationEngine.approve_remediation(
        db=db_session,
        tenant_id=tenant.id,
        remediation_id=rem.id,
        approver_id=user_id,
        user_role="SOC_L2_LEAD",
        is_ai_agent=False,
    )
    remediation_latency = time.perf_counter() - t_rem_start

    # 9. Measure Retest Latency
    t_retest_start = time.perf_counter()
    retest_result = await RetestEngine.retest_finding(
        db=db_session,
        tenant_id=tenant.id,
        finding_id=target_finding.id,
        user_id=user_id,
        user_role="SOC_L2_LEAD",
    )
    retest_latency = time.perf_counter() - t_retest_start

    # 10. Memory Usage
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    peak_mem_mb = peak_mem / (1024 * 1024)
    total_time = time.perf_counter() - t_global_start

    # Assertions on volume and results
    assert len(events) == 10000
    assert len(incidents) == 100
    assert len(assessments) == 100
    assert len(findings) == 1000
    assert sim_result.simulation_status == "PASS"
    assert retest_result["detection_status"] == "PASS"

    # Print benchmark report for audit
    print("\n" + "=" * 60)
    print("           AEGISSOC PHASE 4 PERFORMANCE BENCHMARK           ")
    print("=" * 60)
    print("Dataset Volume:")
    print(f"  - Telemetry Events:       {len(events):,} events")
    print(f"  - Correlated Incidents:   {len(incidents):,} incidents")
    print(f"  - Validation Assessments: {len(assessments):,} assessments")
    print(f"  - Security Findings:      {len(findings):,} findings")
    print("-" * 60)
    print("Latency Measurements:")
    print(f"  - Assessment Creation:    {create_latency * 1000.0:.2f} ms / assessment")
    print(f"  - Detection Evaluation:   {detection_latency * 1000.0:.2f} ms")
    print(f"  - Simulation Pipeline:    {simulation_latency * 1000.0:.2f} ms")
    print(f"  - Gap Analysis:           {gap_latency * 1000.0:.4f} ms")
    print(f"  - Remediation Workflow:   {remediation_latency * 1000.0:.2f} ms")
    print(f"  - Retest Pipeline:        {retest_latency * 1000.0:.2f} ms")
    print("-" * 60)
    print("System Resource Consumption:")
    print(f"  - Peak Memory:            {peak_mem_mb:.2f} MB")
    print(f"  - Total Benchmark Time:   {total_time:.2f} s")
    print("=" * 60 + "\n")
