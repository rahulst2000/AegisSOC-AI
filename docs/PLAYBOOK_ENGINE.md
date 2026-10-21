# AegisSOC AI — Playbook Engine

## 1. Overview & Architecture

The AegisSOC AI Playbook Engine manages controlled, deterministic incident response actions. It implements a strict state machine with human authorization gates, preventing autonomous destructive actions:

```
AI Investigation Recommendation
               ↓
   Policy Engine Evaluation
(Safety Rules & Tenant Constraints)
               ↓
     Action Request Created
      (Status: REQUESTED)
               ↓
      Human Analyst Review
   [APPROVE]        [REJECT]
       |                |
       v                v
 (Status: APPROVED)  (Status: REJECTED)
       |
       v
 Playbook Executor Invocations
 (Lab / Mock Response Adapters)
       ↓
  Execution Telemetry Captured
  (Before State + Action + After State)
       ↓
  Response Verification Engine
   [MATCH]          [MISMATCH]
       |                |
       v                v
(Status: VERIFIED)   (Status: VERIFICATION_FAILED)
                        + Alert Created for SOC Review
       ↓
Immutable Tenant Audit Log Recorded
```

---

## 2. Playbook Catalog

AegisSOC AI implements six standard defensive playbooks defined in [`backend/app/playbooks/registry.py`](file:///c:/Users/Rahul/OneDrive/Desktop/AegisSOC/backend/app/playbooks/registry.py):

| Playbook ID | Name | Action Type | Required Role | Reversible |
|---|---|---|:---:|:---:|
| `PLAYBOOK-001` | Account Lockout Recommendation | `ACCOUNT_LOCKOUT` | `SOC_L1_ANALYST` | Yes |
| `PLAYBOOK-002` | IP Containment Recommendation | `IP_CONTAINMENT` | `SOC_L1_ANALYST` | Yes |
| `PLAYBOOK-003` | Session Revocation Recommendation | `SESSION_REVOCATION` | `SOC_L1_ANALYST` | Yes |
| `PLAYBOOK-004` | Host Isolation Recommendation | `HOST_ISOLATION` | `SOC_L2_LEAD` | Yes |
| `PLAYBOOK-005` | Incident Escalation to L2 | `L2_ESCALATION` | `SOC_L1_ANALYST` | No |
| `PLAYBOOK-006` | Collect Additional Evidence | `COLLECT_EVIDENCE` | `SOC_L1_ANALYST` | Yes |

---

## 3. Action Lifecycle State Machine

Every action request transitions through explicitly defined lifecycle states:

```
REQUESTED
  ├─> REJECTED (Terminal)
  └─> APPROVED
        └─> EXECUTING
              ├─> FAILED (Adapter execution error)
              └─> SUCCEEDED
                    ├─> VERIFIED (Verified state change confirmed)
                    └─> VERIFICATION_FAILED (State change did not match expectation)
```

### Invariants:
1. `execute_approved_action` explicitly asserts `action.approval_status == "APPROVED"`. Any attempt to execute an unapproved or rejected action fails immediately with a `ValueError`.
2. Execution captures both `evidence_before` and `evidence_after` states.
3. Every state transition is recorded in the tenant-isolated audit log.

---

## 4. Controlled Lab Adapters

To guarantee safety and prevent accidental disruption of production networks in Phase 3, response actions execute via simulated lab adapters defined in [`backend/app/playbooks/actions.py`](file:///c:/Users/Rahul/OneDrive/Desktop/AegisSOC/backend/app/playbooks/actions.py):
- **`MockFirewallAdapter`**: Simulates perimeter firewall rule injection (`ALLOWED` $\to$ `DENIED`).
- **`MockIdentityAdapter`**: Simulates Active Directory / IdP account lockouts and session invalidations (`ACTIVE` $\to$ `LOCKED`).
- **`MockEndpointAdapter`**: Simulates EDR endpoint isolation (`CONNECTED` $\to$ `ISOLATED`).
