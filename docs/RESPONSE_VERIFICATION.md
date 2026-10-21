# AegisSOC AI — Response Verification Engine

## 1. Overview & Verification Paradigm

In traditional security automation (SOAR), response actions are frequently marked "completed" simply because an API returned an HTTP 200 status code. In real environments, firewall API rules may fail to commit, sessions may fail to terminate due to token caching, and host network isolation scripts may terminate prematurely.

AegisSOC AI enforces an explicit verification invariant:
> **Never assume execution succeeded. Never claim response success without state-based verification.**

```
   Pre-Execution State Capture (evidence_before)
                       ↓
   Action Execution (Adapter / Device API)
                       ↓
   Post-Execution State Capture (evidence_after)
                       ↓
      Verification Engine Comparison
      [evidence_before != evidence_after]
           /                         \
         YES                          NO
          v                            v
[VERIFIED Status]           [VERIFICATION_FAILED Status]
                                       ↓
                            Alert Created for SOC Review
```

---

## 2. Verification Protocol per Action Type

Defined in [`backend/app/playbooks/verification.py`](file:///c:/Users/Rahul/OneDrive/Desktop/AegisSOC/backend/app/playbooks/verification.py):

| Action Type | Before State Requirement | Expected After State | Verification Rule |
|---|---|---|---|
| `IP_CONTAINMENT` | `traffic_status == "ALLOWED"` | `traffic_status == "DENIED"` | Before state was open and after state is blocked |
| `ACCOUNT_LOCKOUT` | `account_status == "ACTIVE"` | `account_status == "LOCKED"` | IdP verifies account locked flag is set |
| `SESSION_REVOCATION` | `active_sessions > 0` | `active_sessions == 0` | Token revocation confirmed across auth brokers |
| `HOST_ISOLATION` | `network_state == "CONNECTED"` | `network_state == "ISOLATED"` | Host unreachable on general ports, telemetry preserved |
| `COLLECT_EVIDENCE` | Pre-acquisition disk/mem hash | Package SHA-256 computed | Target telemetry successfully staged |

---

## 3. Failure Handling & Alerting

If an action cannot be verified:
1. The execution is marked `verification_status="VERIFICATION_FAILED"` and `execution_status="FAILED"`.
2. An error message detailing the reason is persisted in `action_requests.error`.
3. An automated SOC alert (`Alert`) is created with severity `HIGH` and rule `VERIFICATION_FAILED:{action_type}`.
4. An audit event `ACTION_FAILED` is logged with the full telemetry diff.
5. The SOC analyst is notified via the incident UI.
