# Continuous Security Improvement & Posture Engine

The Continuous Security Improvement engine turns adversary simulation results into auditable, actionable hardening workflows.

---

## 1. Closed-Loop Security Lifecycle

```
[Adversary Simulation]
        │
        ▼
[Defensive Pipeline Execution]
        │
        ▼
[Gap Analysis Engine]
        │
        ▼
[Security Finding Created (OPEN)]
        │
        ▼
[Remediation Action Proposed (PENDING)]
        │
        ▼
[Human Sign-Off & Approval (SOC_L2_LEAD / SOC_ADMIN)]
        │
        ▼
[Rule / Configuration Update Applied]
        │
        ▼
[Automated Retest with Regression Protection]
        │
        ▼
[Finding Status: VERIFIED]
```

---

## 2. Distinction: Test Coverage vs Overall Security Posture

- **Test Coverage**: Calculated strictly from the ratio of successfully detected and validated techniques over the set of *tested* techniques:
  $$\text{Coverage} = \frac{\text{Passed Techniques}}{\text{Total Tested Techniques}} \times 100\%$$
- **Overall Security Posture**: A composite scoring across 7 core defensive categories:
  1. Identity Security
  2. Detection Coverage
  3. Incident Response
  4. Endpoint Security
  5. Network Security
  6. Vulnerability Management
  7. Security Monitoring

All posture numbers reflect verified evidence; metrics are never synthesized or fabricated.

---

## 3. Human Gate Invariant

To preserve operational stability:
- Autonomous agents **cannot** modify active production Sigma rules.
- Autonomous agents **cannot** alter firewall or access policies without human review.
- Remediation approval requires explicit sign-off from `SOC_L2_LEAD` or `SOC_ADMIN`.
