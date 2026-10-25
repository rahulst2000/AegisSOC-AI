# AegisSOC AI — REST API Documentation (v1)

Base URL: `/api/v1`

---

## 1. System Health
### `GET /health` / `GET /api/v1/health`
Checks backend responsiveness and live database connectivity.
- **Authentication**: None
- **Response**:
  ```json
  {
    "status": "healthy",
    "service": "AegisSOC AI",
    "version": "0.1.0",
    "environment": "development",
    "timestamp": "2026-10-21T12:00:00Z",
    "database": "connected"
  }
  ```

---

## 2. Authentication
### `POST /api/v1/auth/register`
Provisions an initial organization tenant and administrative user.
- **Payload**:
  ```json
  {
    "organization_name": "Lockheed Cyber Ops",
    "email": "lead@lockheed.internal",
    "password": "DEMO_PASSWORD=<configure locally>",
    "role": "TENANT_ADMIN"
  }
  ```
- **Response (201 Created)**: Returns access and refresh JWT tokens alongside user profile.

### `POST /api/v1/auth/login`
Authenticates existing users with constant-time password verification.
- **Payload**:
  ```json
  {
    "email": "lead@lockheed.internal",
    "password": "DEMO_PASSWORD=<configure locally>"
  }
  ```
- **Response (200 OK)**: Returns JWT bearer tokens.

### `GET /api/v1/auth/me`
Retrieves the caller's active user profile and tenant identity.
- **Authentication**: Bearer Token required.

---

## 3. Tenants
### `POST /api/v1/tenants`
Provisions a new tenant. Restricted to `TENANT_ADMIN` or `CISO`.
- **Payload**: `{"name": "Subsidiary Tenant"}`

### `GET /api/v1/tenants/me`
Returns metadata of the caller's authenticated tenant organization.

---

## 4. Assets
### `POST /api/v1/assets`
Registers an infrastructure asset under the caller's tenant.
- **Payload**:
  ```json
  {
    "hostname": "k8s-master-01.aegis.internal",
    "ip_address": "10.0.1.10",
    "asset_type": "SERVER",
    "criticality": "HIGH",
    "environment": "PRODUCTION",
    "status": "ACTIVE"
  }
  ```

### `GET /api/v1/assets`
Lists all assets belonging strictly to the caller's tenant.

---

## 5. Security Events
### `POST /api/v1/events`
Ingests telemetry events into the tenant's data lake. Automatically creates detection alerts for `HIGH` or `CRITICAL` events.
- **Payload**:
  ```json
  {
    "source": "CrowdStrike-Falcon",
    "event_type": "SUSPICIOUS_SCRIPT_EXECUTION",
    "severity": "HIGH",
    "source_ip": "10.0.5.22",
    "raw_event": {"command": "powershell.exe -enc ..."}
  }
  ```

### `GET /api/v1/events`
Lists paginated security events for the caller's tenant.

---

## 6. Alerts
### `GET /api/v1/alerts`
Lists detection alerts triggered within the caller's tenant.

---

## 7. Incidents
### `POST /api/v1/incidents`
Creates a new forensic incident.
- **Payload**:
  ```json
  {
    "title": "Credential Dumping via Mimikatz",
    "description": "LSASS memory handle opened by unauthorized utility.",
    "severity": "CRITICAL",
    "risk_score": 90.0,
    "confidence": 0.98,
    "status": "INVESTIGATING"
  }
  ```

### `GET /api/v1/incidents`
Lists all security incidents for the caller's tenant.

### `GET /api/v1/incidents/{incident_id}`
Retrieves a specific incident. Returns **404 Not Found** if the incident belongs to another tenant or does not exist.
