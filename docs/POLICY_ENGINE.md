# AegisSOC AI — Policy Engine

## 1. Overview & Policy Hierarchy

The AegisSOC AI Policy Engine evaluates whether a proposed response action is legally, operationally, and technically permissible. The engine enforces an inviolable hierarchy:

```
Platform Safety Rules (Inviolable System Constraints)
                    ↓
Company Security Policy (Tenant Master Configuration)
                    ↓
Environment Policy (Production vs Staging vs Corporate)
                    ↓
Asset Criticality Policy (Domain Controllers, Payment Gateways)
                    ↓
Role Authorization Gates (SOC_L1 vs SOC_L2 vs SOC_ADMIN)
                    ↓
Action Authorization Decision (ALLOW / REQUIRE_APPROVAL / DENY)
```

---

## 2. Platform Safety Rules (Inviolable)

Platform safety rules reside in [`backend/app/policy/defaults.py`](file:///c:/Users/Rahul/OneDrive/Desktop/AegisSOC/backend/app/policy/defaults.py) and **cannot be overridden by any tenant policy**:

1. **Loopback & Local Interface Protection**:
   Containment of `127.0.0.1`, `127.0.0.0/8`, `::1`, `localhost`, `0.0.0.0` is strictly forbidden.
2. **Broadcast & Multicast Protection**:
   Containment targeting `255.255.255.255` or multicast subnets (`224.0.0.0/4`) is blocked.
3. **Break-Glass Identity Protection**:
   Standard playbooks cannot disable hard-coded break-glass emergency administrative identities (`breakglass`, `emergency-admin`).

Any action violating platform safety rules is rejected immediately with:
`decision="DENIED"`, `reason="Platform Safety Violation: Containment of IP ... is strictly forbidden"`.

---

## 3. Tenant Custom Security Policies

Tenants can customize response behavior per action type in `SecurityPolicy` records:

| Field | Description | Example |
|---|---|---|
| `action_type` | Targeted response action type | `IP_CONTAINMENT` |
| `is_enabled` | Master switch for the action | `True` / `False` |
| `requires_approval` | Requires human sign-off before execution | `True` |
| `required_role` | Minimum role authorized to approve | `SOC_L1_ANALYST` or `SOC_L2_LEAD` |
| `prohibited_targets` | Tenant-specific denylist of exempt assets | `["10.0.0.1", "prod-db-primary"]` |
| `auto_execute` | Autonomous execution without human gate | `False` (Mandatory for Phase 3) |

### Tenant Isolation:
All policy lookups are constrained to the tenant:
```sql
SELECT * FROM security_policies WHERE tenant_id = :tenant_id AND action_type = :action_type;
```
A policy defined in Tenant A never impacts Tenant B.
