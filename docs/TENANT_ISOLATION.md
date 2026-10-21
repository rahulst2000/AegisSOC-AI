# AegisSOC AI — Tenant Isolation Architecture

## 1. Overview
Multi-tenancy in AegisSOC AI is designed with strict logical partition isolation. In a multi-tenant cybersecurity environment, preventing data leakage across distinct organizations or business units is paramount.

---

## 2. Core Isolation Rules

1. **Every Security Object Contains `tenant_id`**:
   All database tables storing security assets, events, alerts, incidents, evidence, and audit trails include a non-nullable `tenant_id` foreign key referencing `tenants.id`.

2. **Never Trust Client-Supplied `tenant_id`**:
   Client request bodies and query parameters are prohibited from dictating the active `tenant_id`. If a malicious actor injects `{"tenant_id": "other-tenant-uuid"}` in a payload, the server discards the field and enforces `tenant_id = current_user.tenant_id`.

3. **Server-Side Tenant Context Derivation**:
   The `tenant_id` is established strictly by decoding and verifying the cryptographic signature of the authenticated JWT token issued during `/auth/login`.

4. **Zero Cross-Tenant Queries**:
   Database access layers apply mandatory predicates:
   ```python
   stmt = select(Incident).where(
       Incident.id == incident_id,
       Incident.tenant_id == current_user.tenant_id
   )
   ```

5. **Safe Denial Semantics (HTTP 404 vs 403)**:
   When Tenant A requests an ID belonging to Tenant B, the server responds with **HTTP 404 Not Found**.
   - **Rationale**: An HTTP 403 would confirm to an adversary that a resource exists with that specific ID (oracle enumeration attack). Returning 404 guarantees that unauthorized resources remain completely invisible.

---

## 3. Dedicated Verification Tests
Cross-tenant isolation is continuously verified in the automated CI test suite in `backend/tests/test_cross_tenant_isolation.py`:
- `test_cross_tenant_incident_access_denied`: Confirms 404 response on foreign incident access.
- `test_cross_tenant_asset_isolation`: Confirms 0 assets returned when Tenant B lists inventory.
- `test_cross_tenant_event_isolation`: Confirms Tenant B receives zero events from Tenant A.
- `test_cross_tenant_alerts_isolation`: Confirms alerts triggered in Tenant A do not appear in Tenant B's feed.
