# AegisSOC AI — Forensic Evidence Model & Integrity Specification

## 1. Core Principles

A fundamental requirement of AegisSOC AI is **strict forensic groundedness**:
- **Never Invent Evidence**: Every detection, alert, and incident is directly traced back to authoritative, normalized security event IDs. If a rule cannot establish its required evidence, no confirmed detection is generated.
- **Forensic Immutability**: Evidence records are immutable and validated using cryptographic hashes.
- **Tenant Scope Binding**: Evidence items are partitioned strictly by `tenant_id`. Cross-tenant linkage is prohibited by database constraints and software invariants.

---

## 2. Integrity Hash Computation (SHA-256)

When a security event is linked as evidence for a detection, a deterministic cryptographic SHA-256 integrity hash is computed from the underlying telemetry:

```python
def compute_evidence_hash(event: SecurityEvent) -> str:
    raw_payload_bytes = json.dumps(
        event.raw_event,
        sort_keys=True,
        default=str,
    ).encode("utf-8")

    digest = hashlib.sha256()
    digest.update(str(event.id).encode("utf-8"))
    digest.update(str(event.tenant_id).encode("utf-8"))
    digest.update(event.timestamp.isoformat().encode("utf-8"))
    digest.update(raw_payload_bytes)
    return digest.hexdigest()
```

This guarantees:
1. Proof of existence at the recorded timestamp.
2. Tamper-evident detection of any post-hoc modifications to event payloads.
3. Tenant attribution immutability.

---

## 3. Evidence Lifecycle in the Pipeline

```
SecurityEvent (EVT-1001, EVT-1002, ...)
      ↓ (Matched by DetectionRule)
DetectionResult (event_ids = [EVT-1001, EVT-1002])
      ↓
Evidence (tenant_id, event_id, evidence_type="EVENT_TELEMETRY", integrity_hash=SHA256(...))
      ↓ (Correlated into Incident)
Incident (evidence_items linked via Evidence.incident_id)
```

1. **Detection Match**: Detection matches record the concrete `event_ids` that caused the rule condition to be satisfied.
2. **Evidence Record**: An `Evidence` record is created for each matched event containing the cryptographic SHA-256 integrity hash and description.
3. **Incident Correlation**: When detections are correlated, unlinked `Evidence` items are assigned `incident_id = incident.id`.
4. **Chronological Forensic Timeline**: Analysts can inspect the complete evidentiary chain via `GET /api/v1/incidents/{incident_id}/timeline`.
