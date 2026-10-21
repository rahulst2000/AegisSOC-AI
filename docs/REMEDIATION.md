# Remediation Workflow & Human-in-the-Loop Governance

Remediation turns identified detection gaps into validated security improvements while strictly protecting production stability.

---

## 1. Remediation Status Progression

```
[OPEN]
   │ (Operator creates proposed change)
   ▼
[UNDER_REMEDIATION]
   │ (Proposed change submitted for review)
   ▼
[RemediationAction: PENDING]
   │ (Human sign-off from SOC_L2_LEAD or SOC_ADMIN)
   ▼
[RemediationAction: APPROVED]
   │ (Change applied in test environment)
   ▼
[Automated Retest Executed]
   ├── If Retest Passes & Regressions Pass ──► [VERIFIED] ──► [CLOSED]
   ├── If Retest Passes but Regressions Fail ──► [REMEDIATION_FAILED]
   └── If Retest Still Fails ───────────────► [PARTIALLY_REMEDIATED]
```

---

## 2. Guardrails Against Autonomous Modification

- **Human Review**: AI agents can suggest rule tuning or allowlists, but cannot approve remediation actions.
- **Rule Isolation**: Changes are staged and validated against lab targets before any consideration for production rollout.
- **Role Verification**: Only users with `SOC_L2_LEAD` or `SOC_ADMIN` roles can approve remediations.
