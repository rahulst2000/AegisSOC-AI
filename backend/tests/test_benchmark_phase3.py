import time
import tracemalloc
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.provider import DeterministicAIProvider
from app.investigation.evidence_collector import EvidenceCollector
from app.models.event import SecurityEvent
from app.models.tenant import Tenant
from app.playbooks.actions import MockFirewallAdapter
from app.playbooks.verification import verify_response_action


@pytest.mark.asyncio
async def test_benchmark_phase3_performance(db_session: AsyncSession):
    """
    Phase 3 Performance Benchmark:
    - 10,000 Security Events Evidence Retrieval
    - 100 Incidents Full Autonomous Investigation
    - 1,000 Incidents AI Analysis
    - Playbook Execution & Response Verification Latency
    - Peak Memory Usage
    """
    tracemalloc.start()
    _ = time.perf_counter()

    tenant = Tenant(name="Benchmark Phase 3 Tenant")
    db_session.add(tenant)
    await db_session.flush()

    # 1. Generate 10,000 Synthetic Events
    base_time = datetime.now(UTC)
    events: list[SecurityEvent] = []
    for i in range(10000):
        evt = SecurityEvent(
            tenant_id=tenant.id,
            source="benchmark_telemetry",
            event_type="authentication_failure" if i % 2 == 0 else "authentication_success",
            severity="MEDIUM" if i % 2 == 0 else "LOW",
            source_ip=f"198.51.100.{1 + (i % 250)}",
            username=f"bench_user_{i % 500}",
            hostname=f"node-{(i % 50):02d}.internal",
            timestamp=base_time + timedelta(seconds=i),
            raw_event={"auth": {"result": "failure" if i % 2 == 0 else "success"}},
            normalized_event={"event": {"type": "authentication_failure" if i % 2 == 0 else "authentication_success"}},
        )
        events.append(evt)

    db_session.add_all(events)
    await db_session.flush()

    # 2. Benchmark Evidence Retrieval Latency across 10,000 events
    t_retrieval_start = time.perf_counter()
    collector = EvidenceCollector(db_session, tenant.id)
    retrieved_events = await collector.search_events(limit=100)
    retrieved_auth = await collector.get_authentication_history("bench_user_1", limit=20)
    retrieval_time = time.perf_counter() - t_retrieval_start

    assert len(retrieved_events) == 100
    assert len(retrieved_auth) >= 1

    # 3. Benchmark 100 Incidents Full Investigation
    provider = DeterministicAIProvider()
    t_100_start = time.perf_counter()
    for k in range(100):
        sample_context = {
            "incident": {
                "id": str(uuid.uuid4()),
                "title": f"Bench Incident {k}",
                "risk_score": 75,
                "confidence_score": 0.85,
                "mitre_techniques": ["T1110.001"],
                "source_ips": [f"198.51.100.{(k % 20) + 1}"],
                "affected_users": [f"user_{k}"],
                "affected_assets": [f"node-{(k % 10):02d}.internal"],
            },
            "detections": [
                {
                    "rule_id": "SIGMA-SSH-BRUTEFORCE",
                    "title": "SSH Brute Force",
                    "severity": "HIGH",
                    "confidence": 0.95,
                    "mitre_techniques": ["T1110.001"],
                    "event_ids": [str(events[k * 5 + j].id) for j in range(5)],
                }
            ],
            "events": [
                {
                    "id": str(events[k * 5 + j].id),
                    "raw_payload": "",
                    "normalized_event": events[k * 5 + j].normalized_event,
                }
                for j in range(5)
            ],
        }
        res = await provider.analyze(sample_context)
        assert len(res.hypotheses) == 8

    time_100_incidents = time.perf_counter() - t_100_start

    # 4. Benchmark 1,000 Incidents Fast AI Evaluation
    t_1000_start = time.perf_counter()
    fast_context = {
        "incident": {
            "id": str(uuid.uuid4()),
            "title": "Fast Incident",
            "risk_score": 60,
            "confidence_score": 0.80,
            "mitre_techniques": ["T1110"],
            "source_ips": ["198.51.100.5"],
            "affected_users": ["test_user"],
            "affected_assets": ["host1"],
        },
        "detections": [],
        "events": [],
    }
    for _ in range(1000):
        await provider.analyze(fast_context)
    time_1000_incidents = time.perf_counter() - t_1000_start

    # 5. Benchmark Playbook Execution & Response Verification Latency
    t_playbook_start = time.perf_counter()
    for _ in range(100):
        adapter_output = MockFirewallAdapter.block_ip("198.51.100.50")
        ver = verify_response_action(
            action_type="IP_CONTAINMENT",
            before_state=adapter_output["before"],
            after_state=adapter_output["after"],
            adapter_success=adapter_output["success"],
        )
        assert ver.verified is True
    time_playbooks = time.perf_counter() - t_playbook_start

    # 6. Memory Peak
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_mb = peak_mem / (1024 * 1024)

    ms_per_inc = (time_100_incidents / 100) * 1000
    inc_per_sec = 1000 / time_1000_incidents
    ms_per_action = (time_playbooks / 100) * 1000

    print("\n--- PHASE 3 PERFORMANCE BENCHMARK RESULTS ---")
    print(f"Total Synthetic Events Ingested: {len(events):,}")
    print(f"Evidence Retrieval Latency (10k indexed events): {retrieval_time * 1000:.2f} ms")
    print(f"100 Incidents Investigation Time: {time_100_incidents:.4f} s ({ms_per_inc:.2f} ms / incident)")
    print(f"1,000 Incidents Evaluation Time: {time_1000_incidents:.4f} s ({inc_per_sec:.1f} incidents/sec)")
    print(
        f"Playbook Execution & Verification (100 runs): {time_playbooks * 1000:.2f} ms ({ms_per_action:.2f} ms / act)"
    )
    print(f"Peak Memory Usage: {peak_mb:.2f} MB")
    print("--------------------------------------------\n")

    assert time_100_incidents < 5.0
    assert time_1000_incidents < 10.0
    assert peak_mb < 200.0
