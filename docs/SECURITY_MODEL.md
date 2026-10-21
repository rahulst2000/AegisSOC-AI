# AegisSOC AI — Security Model & Governance

## 1. Principles of Defensive Cybersecurity

AegisSOC AI is built from the ground up as a defensive cybersecurity platform.
All engineering practices adhere strictly to the following security covenants:

1. **Explicit Lab Authorization**: All validation testing and adversary emulation must occur in explicitly authorized lab/staging environments.
2. **No Autonomous Destructive Actions**: The system never executes destructive, irreversible, or offensive operations without explicit, human-in-the-loop authorization.
3. **Decoupled AI Recommendations**: Future LLM reasoning components generate proposed remediation plans and correlation hypotheses, but never directly execute changes to firewalls, cloud infrastructure, or host configurations.
4. **No Synthetic Security Deception**: Security metrics, detection alerts, and audit logs are never fabricated.

---

## 2. Authentication & Credential Architecture

### 2.1 Password Security
- Plaintext passwords are never logged, stored, or echoed back.
- Passwords are hashed using **bcrypt** with individual salt generation at cost factor 12.
- Password verification executes in constant time to thwart timing analysis attacks.

### 2.2 JWT Tokens
- Tokens are cryptographically signed using `HS256` (or `RS256` in enterprise deployments) with a minimum 256-bit entropy secret key.
- Payloads embed:
  - `sub`: User UUID
  - `tenant_id`: Immutable Tenant UUID
  - `role`: User role
  - `exp`: Expiration Unix epoch
  - `iat`: Issued-at epoch
- Token signatures, exp, and format are verified on every authenticated API invocation.

---

## 3. Role-Based Access Control (RBAC) Matrix

| Role | Scope & Permissions | Typical User Persona |
| :--- | :--- | :--- |
| **TENANT_ADMIN** | Full administrative rights over tenant configuration, user invites, role management, asset registration. | IT / SOC Director |
| **CISO** | Read-only executive visibility across all incidents, risk scores, compliance metrics, and audit logs. | Chief Information Security Officer |
| **SECURITY_MANAGER** | Incident lifecycle management, escalation handling, team workflow supervision. | SOC Manager |
| **SECURITY_ENGINEER** | Telemetry ingestion configuration, asset onboarding, detection rule tuning, incident creation. | Threat Hunter / SecOps Engineer |
| **SOC_L2** | Advanced incident triage, forensic evidence association, containment recommendation. | Senior Incident Responder |
| **SOC_L1** | Initial alert queue triage, basic event query, incident assignment. Prohibited from asset/tenant modification. | Junior SOC Analyst |
| **GRC_ANALYST** | Compliance reporting, evidence audit inspection, policy review. Prohibited from mutating active alerts. | Compliance Auditor |

---

## 4. Audit Logging & Non-Repudiation
Every security-relevant operation creates an immutable entry in the `audit_logs` table:
- **Tenant Attribution**: `tenant_id`
- **Actor Identity**: `user_id` (null if unauthenticated)
- **Action Performed**: e.g. `AUTH_LOGIN`, `USER_REGISTRATION`, `CREATE_ASSET`, `CREATE_INCIDENT`
- **Resource Scope**: Entity type and primary key
- **Outcome**: `SUCCESS`, `FAILURE`, or `DENIED`
- **Metadata**: Request correlation ID, client IP, user agent, and non-sensitive parameters
