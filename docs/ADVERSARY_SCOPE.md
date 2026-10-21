# AegisRed: Authorization & Scope Control Specification

Scope control is the foremost safety guarantee of AegisRed. Under no circumstances may simulations target arbitrary internet assets, external hosts, or production corporate environments.

---

## 1. Scope Schema (`AUTHORIZED_SCOPE`)

Before any assessment can transition from `DRAFT` to `AUTHORIZED`, or execute in `RUNNING`, an explicit `authorized_scope` payload must be provided and validated.

```json
{
  "environment": "LAB",
  "assets": ["lab-server-01"],
  "hostnames": ["lab-server-01.local"],
  "ips": ["10.0.0.50"],
  "allowed_techniques": ["T1110.001"],
  "prohibited_techniques": [
    "persistence",
    "data_exfiltration",
    "destructive_actions"
  ],
  "expires_at": "2026-10-22T12:00:00Z",
  "authorized_by": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
}
```

---

## 2. Hard Invariant Rules Enforced by Scope Validator

The authoritative scope validator (`app.adversary.scope.validate_assessment_scope`) rejects any assessment exhibiting:

1. **Production Environment**:
   - Any assessment where `environment == "PRODUCTION"` is rejected with `Platform Safety Violation`.
   - Any environment other than `LAB` is rejected.
2. **Production Asset Indicators**:
   - Any target asset name containing `prod` (e.g. `prod-db-01`, `prod-gateway`) is rejected immediately, even if labeled `LAB`.
3. **Prohibited Techniques**:
   - Explicitly prohibited offensive classes (`persistence`, `data_exfiltration`, `destructive_actions`, `credential_dumping`, `lateral_movement`) are blocked.
4. **Technique Whitelisting**:
   - The executed technique must be explicitly present in `allowed_techniques`.
5. **Expired Authorization**:
   - If `expires_at <= datetime.now(UTC)`, the assessment is rejected with `Scope authorization expired`.
6. **Missing Human Authorization Signature**:
   - `authorized_by` is mandatory; autonomous execution without a human approver is impossible.
7. **Protected IP / Loopback Restrictions**:
   - Target IPs matching `127.0.0.1`, `::1`, or reserved critical infrastructure IPs are rejected with `Platform Safety Violation`.

---

## 3. Strict Boundary: AI Cannot Modify Scope

- AI models, subagents, or automated workflows **cannot**:
  - Add or modify target assets, hostnames, or IPs.
  - Expand allowed MITRE techniques.
  - Extend expiration dates.
  - Sign off as `authorized_by`.
- All scope changes require human authentication with verified JWT and RBAC clearance (`SOC_L2`, `SECURITY_ENGINEER`, `SECURITY_MANAGER`, `TENANT_ADMIN`, `CISO`).
