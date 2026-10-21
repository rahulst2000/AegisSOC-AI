# Automated Retesting & Regression Protection

Remediation without retesting is assumption. AegisSOC AI enforces that security findings can only be marked `VERIFIED` through empirical re-execution.

---

## 1. Automated Retest Flow

When `POST /api/v1/security-improvement/findings/{finding_id}/retest` is invoked:

1. **Scope Verification**: Ensures the original assessment scope is still valid and restricted to `LAB`. If the scope has expired or targets a prohibited host, retesting is aborted.
2. **Scenario Re-Execution**: Re-runs the exact adversary validation scenario (`SCENARIO-001` through `SCENARIO-004`).
3. **Regression Testing**: Automatically runs baseline detection checks across adjacent scenarios (e.g. ensuring an SSH brute-force fix did not break password spraying or normal single-login evaluation).
4. **Outcome Transition**:
   - Both scenario and regression pass $\implies$ Finding status updated to `VERIFIED`.
   - Scenario passes but regression fails $\implies$ Finding status marked `REMEDIATION_FAILED` to prevent regressions from polluting production rules.
   - Scenario fails $\implies$ Finding status set to `PARTIALLY_REMEDIATED` or left `UNDER_REMEDIATION`.

---

## 2. Hard Verification Guarantee

No finding can transition to `VERIFIED` without a passing retest execution log and verifiable evidence IDs. Attempting to mark a finding `VERIFIED` manually or via an AI prompt without an empirical retest is prohibited by the service layer.
