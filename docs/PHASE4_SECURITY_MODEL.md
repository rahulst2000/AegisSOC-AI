# Phase 4 Security Model: Adversary Validation Safety & AI Boundaries

AegisSOC AI Phase 4 implements strict defensive constraints to ensure adversary validation cannot be abused or weaponized.

---

## 1. Safety Boundaries

1. **LAB Environment Restriction**: All simulations require an explicit `LAB` environment designation. Any attempt to target `PRODUCTION` or environments containing production naming indicators is blocked.
2. **Prohibited Offensive Behaviors**:
   - Zero internet-wide port or IP scanning.
   - Zero real exploit payloads or remote code execution.
   - Zero persistence mechanisms (e.g. cronjobs, scheduled tasks, registry modifications).
   - Zero real credential theft or dumping (mimikatz, SAM dump, etc.).
   - Zero lateral movement across real subnets.
   - Zero destructive data modification or encryption.
3. **Mandatory Post-Execution Cleanup**:
   - Cleanup handlers execute on every scenario completion or unexpected exception.
   - Restores mock firewall rules, accounts, and temp telemetry.

---

## 2. AI Model Security Boundaries

In accordance with Phase 3 prompt-injection defenses and Phase 4 safety directives:

- **AI Cannot Select Targets**: Target assets and IPs must be selected and approved by humans in the authorized scope.
- **AI Cannot Authorize Assessments**: Assessments must be authorized by human operators with verified JWT tokens.
- **AI Cannot Execute Attacks**: The execution trigger is strictly human-invoked via authenticated API endpoints.
- **AI Cannot Expand Scope**: Scope modifications can only be applied by authenticated human users with appropriate RBAC roles.
- **AI Cannot Mark Findings Verified**: Findings can only become `VERIFIED` via empirical retest executions.
- **AI Cannot Deploy Rule Changes**: Rule modifications require human approval from `SOC_L2_LEAD` or `SOC_ADMIN`.
- **AI Recommendations Are Grounded**: Gap analysis and tuning recommendations are strictly anchored to empirical test evidence.
