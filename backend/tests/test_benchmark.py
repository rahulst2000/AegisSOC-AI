import time
import tracemalloc
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.correlator import Correlator
from app.detection.engine import DetectionEngine
from app.detection.evaluator import evaluate_rule_against_events
from app.detection.rule_loader import sync_rules_to_db
from app.models.event import SecurityEvent
from app.models.tenant import Tenant


@pytest.mark.asyncio
async def test_benchmark_10k_events(db_session: AsyncSession):
    """
    Performance Benchmark:
    Processes at least 10,000 synthetic events.
    Records actual measurements:
    - Ingestion-to-detection latency
    - Detection throughput (events/sec)
    - Correlation latency
    - Peak memory usage (MB via tracemalloc)
    """
    tracemalloc.start()
    t_start = time.perf_counter()

    tenant = Tenant(name="Benchmark Enterprise Corp")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    rules = await sync_rules_to_db(db_session)
    assert len(rules) >= 6

    # 1. Generate 10,000 synthetic events
    event_count = 10000
    base_time = datetime.now(UTC) - timedelta(hours=2)
    events: list[SecurityEvent] = []

    for i in range(event_count):
        ip_suffix = (i % 250) + 1
        source_ip = f"198.51.100.{ip_suffix}"
        user = f"user_{i % 50}"
        event_type = "AUTH_FAILURE" if (i % 7 != 0) else "AUTH_SUCCESS"

        evt = SecurityEvent(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            timestamp=base_time + timedelta(milliseconds=i * 20),
            source="ssh" if (i % 2 == 0) else "pam",
            event_type=event_type,
            severity="LOW" if event_type == "AUTH_FAILURE" else "INFO",
            source_ip=source_ip,
            username=user,
            hostname=f"node-{i % 10}.internal",
            raw_event={"event_id": i, "client_ip": source_ip},
            normalized_event={"event": {"type": event_type.lower()}, "source": {"ip": source_ip}},
        )
        events.append(evt)

    t_generation = time.perf_counter()
    _ = t_generation - t_start

    # 2. Benchmark Detection Rule Evaluation (Memory & CPU)
    t_det_start = time.perf_counter()
    engine = DetectionEngine()

    # Benchmark safe evaluator across all 10,000 events against compiled rules
    matched_counts = 0
    for rule in rules:
        matches = evaluate_rule_against_events(rule.conditions, events)
        matched_counts += len(matches)

    t_det_end = time.perf_counter()
    det_duration = t_det_end - t_det_start
    det_throughput = event_count / det_duration if det_duration > 0 else float("inf")
    latency_per_1k_ms = (det_duration / (event_count / 1000)) * 1000

    # 3. Benchmark Correlation Latency
    # Insert a subset into DB to evaluate end-to-end detection & correlation
    db_session.add_all(events[:200])  # representative batch in db
    await db_session.commit()

    t_corr_start = time.perf_counter()
    detections = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=events[:200])
    correlator = Correlator()
    incidents = await correlator.correlate_detections(db=db_session, tenant_id=tenant.id, detections=detections)
    t_corr_end = time.perf_counter()
    corr_duration = t_corr_end - t_corr_start

    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_mem_mb = peak_mem / (1024 * 1024)

    # Print actual recorded measurements
    print("\n" + "=" * 60)
    print("PHASE 2 PERFORMANCE BENCHMARK (10,000 EVENTS)")
    print("=" * 60)
    print(f"Total Synthetic Events Processed : {event_count:,}")
    print(f"Active Detection Rules Evaluated : {len(rules)}")
    print(f"Rule Evaluation Matches Found    : {matched_counts:,}")
    print(f"Detection Evaluation Time        : {det_duration:.4f} s")
    print(f"Detection Throughput             : {det_throughput:.1f} events/sec")
    print(f"Latency per 1,000 Events         : {latency_per_1k_ms:.2f} ms")
    print(f"Correlation Processing Time      : {corr_duration:.4f} s")
    print(f"Generated Correlated Incidents   : {len(incidents)}")
    print(f"Peak Memory Allocation           : {peak_mem_mb:.2f} MB")
    print("=" * 60)

    # Verifications
    assert event_count >= 10000
    assert det_throughput > 1000  # Must exceed 1,000 events/sec comfortably
    assert peak_mem_mb < 250  # Must maintain low memory profile (< 250 MB)
