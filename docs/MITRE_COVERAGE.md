# MITRE ATT&CK Continuous Coverage & Validation Matrix

AegisSOC AI tracks defensive coverage against the MITRE ATT&CK framework across five discrete, evidence-grounded stages:

1. **Detection**: Did a detection rule match the simulated adversary telemetry?
2. **Correlation**: Did the correlation engine group the detection into a unified security incident?
3. **Investigation**: Did autonomous investigation analyze the incident and produce high-confidence evidence?
4. **Response**: Did policy and playbook engines generate an appropriate, human-approved containment action?
5. **Verification**: Did response verification confirm effective containment using verifiable state checks?

---

## 1. Validated Techniques Matrix

| Technique ID | Technique Name | Tactic | Detection Rule | Status | Evidence Count |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `T1110.001` | Password Guessing / SSH Brute Force | Credential Access | `AEGIS-SIG-SSH-BRUTEFORCE` | **PASS** | 10 |
| `T1110.003` | Password Spraying | Credential Access | `AEGIS-SIG-PASSWORD-SPRAYING` | **PASS** | 6 |
| `T1078` | Valid Accounts (Failure → Success) | Defense Evasion, Persistence | `AEGIS-SIG-FAILURE-THEN-SUCCESS` | **PASS** | 4 |
| `T1078.003` | Local Accounts (Privileged Login) | Initial Access, Privilege Escalation | `AEGIS-SIG-PRIVILEGED-LOGIN` | **PASS** | 2 |

---

## 2. Evidence Grounding Invariant

A technique **cannot** be reported as `PASS` in the coverage matrix unless verifiable SHA-256 evidence records exist in the database.

- Untested techniques are explicitly categorized as `NOT_TESTED`.
- Pipeline failures at any stage downgrade the overall result from `PASS` to `PARTIAL` or `FAIL`.
- The system never fabricates or hallucinates coverage metrics.
