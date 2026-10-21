# AegisRed: Controlled Adversary Validation Architecture

AegisSOC AI Phase 4 introduces **AegisRed**, an automated, evidence-grounded adversary validation engine that rigorously and safely validates defensive efficacy without offensive risk.

---

## 1. Core Principles & Safety Model

- **Defensive Mission Only**: The objective of AegisRed is **not** to conduct uncontrolled offensive operations or penetrate production networks. The mission is closed-loop validation of detection, correlation, investigation, containment, and verification capabilities.
- **Authorized Scope Invariant**: Simulations can **only** execute within an authorized test scope (`AUTHORIZED_SCOPE`) on dedicated `LAB` environments. Target environments marked `PRODUCTION` are strictly rejected by policy.
- **Controlled Scenarios Only**: Never deploy exploit payloads, persistence implants, real credential dumps, internet-wide scans, or destructive attacks. Telemetry simulations generate authentic security event signals to exercise the SOC detection pipeline safely.
- **Deterministic Cleanup**: Every simulation triggers mandatory cleanup adapters immediately after completion or failure.

---

## 2. Assessment Lifecycle

Every assessment undergoes a deterministic 7-stage lifecycle:

```
[DRAFT]
   │ (Review and validation of scope)
   ▼
[AUTHORIZED]
   │ (Execution initiated by authorized human operator)
   ▼
[RUNNING]
   ├── Phase A: Ingest Safe Simulation Telemetry
   ├── Phase B: Evaluate Detection Rules (Sigma-compatible)
   ├── Phase C: Evaluate Incident Correlation Engine
   ├── Phase D: Trigger Autonomous Investigation & Evidence Validation
   ├── Phase E: Propose & Approve Mock Containment Playbook
   ├── Phase F: Execute Verifiable Response Verification
   └── Phase G: Mandatory Adapter Cleanup
   │
   ▼
[COMPLETED] or [FAILED]
   │
   ▼
[GAP ANALYSIS & SECURITY FINDING GENERATION]
```

### Lifecycle Statuses

- `DRAFT`: Assessment created with requested parameters and target scope; awaiting human authorization.
- `AUTHORIZED`: Target scope signed off by an authorized human operator (`SOC_L2`, `SOC_L2_LEAD`, `SECURITY_ENGINEER`, `SECURITY_MANAGER`, `TENANT_ADMIN`, `CISO`).
- `RUNNING`: Simulation active; telemetry ingested, detection evaluated, response verified, cleanup executed.
- `COMPLETED`: Simulation and defensive pipeline completed; results recorded.
- `FAILED`: Assessment halted due to error, scope invalidation, or pipeline fault.
- `CANCELLED`: Explicitly aborted by operator; triggers immediate emergency cleanup.

---

## 3. Supported Controlled Scenarios

| Scenario ID | Name | MITRE Technique | Target Environment | Detection Rule | Containment Playbook |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SCENARIO-001` | SSH Brute Force Simulation | `T1110.001` | LAB Server (`lab-server-01`) | `AEGIS-SIG-SSH-BRUTEFORCE` | `PB-SSH-BRUTEFORCE-CONTAINMENT` |
| `SCENARIO-002` | Password Spraying Simulation | `T1110.003` | LAB Domain Controller (`lab-ad-01`) | `AEGIS-SIG-PASSWORD-SPRAYING` | `PB-PASSWORD-SPRAYING-CONTAINMENT` |
| `SCENARIO-003` | Failure → Success Auth Simulation | `T1078` | LAB Identity Store (`lab-id-01`) | `AEGIS-SIG-FAILURE-THEN-SUCCESS` | `PB-COMPROMISED-ACCOUNT-CONTAINMENT` |
| `SCENARIO-004` | Privileged Login Simulation | `T1078.003` | LAB Bastion Host (`lab-bastion-01`) | `AEGIS-SIG-PRIVILEGED-LOGIN` | `PB-PRIVILEGED-ACCOUNT-CONTAINMENT` |

---

## 4. Adversary Validation Results Model

Every validation run outputs an immutable `AssessmentResult` recording:
- `assessment_id`: Reference to parent assessment.
- `scenario_id`: Specific scenario tested.
- `technique_id`: MITRE ATT&CK technique validated.
- `simulation_status`: `PASS` | `FAIL` | `NOT_TESTED`
- `detection_status`: `PASS` | `FAIL` | `NOT_TESTED`
- `correlation_status`: `PASS` | `FAIL` | `NOT_TESTED`
- `investigation_status`: `PASS` | `FAIL` | `NOT_TESTED`
- `response_status`: `PASS` | `FAIL` | `NOT_TESTED`
- `verification_status`: `PASS` | `FAIL` | `NOT_TESTED`
- `cleanup_status`: `CLEANED` | `FAILED` | `NOT_TESTED`
- `overall_result`: `PASS` | `FAIL` | `PARTIAL` | `NOT_TESTED`
- `evidence_ids`: Verifiable SHA-256 evidence links.
- `finding_ids`: Security findings automatically populated for identified gaps.
