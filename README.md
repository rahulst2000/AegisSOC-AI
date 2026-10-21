# AegisSOC AI

> **Evidence-Grounded Autonomous Security Operations, Adversary Validation & Continuous Security Improvement Platform**

[![CI Status](https://github.com/Rahul/AegisSOC/actions/workflows/ci.yml/badge.svg)](https://github.com/Rahul/AegisSOC/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Framework-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![React: 18](https://img.shields.io/badge/Frontend-React%2018%20%2B%20TypeScript-61DAFB.svg)](https://react.dev/)

---

## 1. Project Purpose
**AegisSOC AI** is a legitimate defensive cybersecurity operations platform engineered for modern enterprise defense. It bridges the gap between raw telemetry ingestion, automated adversary detection, forensic evidence validation, and continuous security posture improvement. 

### Core Defensive Mission:
- Enforce strict cryptographic tenant boundary isolation.
- Decouple AI recommendations from actual security interventions to guarantee safety.
- Provide forensic non-repudiation with SHA-256 evidence integrity hashing and append-only audit logging.
- Prohibit any destructive action or uncontrolled autonomous offensive activity.

---

## 2. High-Level Architecture
AegisSOC AI is built as a cloud-native, containerized multi-tier system:

- **Frontend**: Single-page application built in **React 18 + TypeScript + Vite**, with dark-mode glassmorphic SOC command center aesthetics, live telemetry indicators, and interactive incident triage.
- **Backend**: Asynchronous high-performance REST API built with **FastAPI / Python 3.12+**, structured JSON logging, correlation IDs (`X-Request-ID`), defense-in-depth security headers, and Pydantic v2 data validation.
- **Data Persistence**: **PostgreSQL 16** with SQLAlchemy 2.0 ORM and Alembic migrations, utilizing composite indices optimized for tenant queries, timestamps, severity, and hostnames.
- **Cache & Jobs**: **Redis 7** for rate limiting, cache storage, and background task queues.

```
AegisSOC AI Platform
 ├── Frontend (Port 3000)      --> Vite / React / TypeScript SOC Dashboard
 ├── Backend (Port 8000)       --> FastAPI, Pydantic, SQLAlchemy 2.0
 ├── Database (Port 5432)      --> PostgreSQL 16 (Tenant-Isolated Schemas)
 └── Cache (Port 6379)         --> Redis 7 (Rate Limiting & Sessions)
```

For detailed architecture diagrams and design rationale, see [`docs/ARCHITECTURE.md`](file:///c:/Users/Rahul/OneDrive/Desktop/AegisSOC/docs/ARCHITECTURE.md).

---

## 3. Technology Stack

| Component | Technology |
| :--- | :--- |
| **Backend** | Python 3.12+, FastAPI, Uvicorn |
| **Database** | PostgreSQL 16, SQLAlchemy 2.0 (Async), Alembic |
| **Validation** | Pydantic v2, Pydantic Settings |
| **Frontend** | React 18, TypeScript, Vite, Lucide Icons |
| **Caching/Jobs** | Redis 7 |
| **Containers** | Docker, Docker Compose |
| **Testing** | Pytest, pytest-asyncio, HTTPX, Vitest, Testing Library |
| **Formatting/Linting**| Ruff (Linter, Formatter, Bandit Security) |
| **CI/CD** | GitHub Actions |

---

## 4. Security Principles

1. **Zero Secrets in Code**: Secrets are never hard-coded. Configurations use `.env.example` and are strictly gitignored.
2. **Never Log Sensitive Data**: Passwords, tokens, keys, and authorization cookies are automatically scrubbed from structured logs.
3. **Server-Side Tenant Derivation**: The server **never** trusts a client-supplied `tenant_id`. All authorization and data filtering stem strictly from cryptographically validated JWT session context.
4. **Denial by Obfuscation (404 on Cross-Tenant)**: Cross-tenant resource queries return `404 Not Found` rather than `403 Forbidden` to prevent oracle enumeration attacks.
5. **Role-Based Access Control**: Strict least-privilege matrix enforcing separation between `TENANT_ADMIN`, `CISO`, `SECURITY_MANAGER`, `SECURITY_ENGINEER`, `SOC_L2`, `SOC_L1`, and `GRC_ANALYST`.
6. **Immutable Audit Trails**: All security-critical actions are recorded in an append-only audit log with correlation IDs.

For our full security specifications, consult:
- [`docs/SECURITY_MODEL.md`](file:///c:/Users/Rahul/OneDrive/Desktop/AegisSOC/docs/SECURITY_MODEL.md)
- [`docs/TENANT_ISOLATION.md`](file:///c:/Users/Rahul/OneDrive/Desktop/AegisSOC/docs/TENANT_ISOLATION.md)

---

## 5. Local Setup & Quickstart

### 5.1 Docker Compose (Recommended)
Launch the entire stack with health checks:
```bash
docker compose up -d --build
```
- Frontend: `http://localhost:3000`
- Backend API Docs: `http://localhost:8000/docs`
- Health check: `http://localhost:8000/health`

### 5.2 Native Local Development

#### Backend:
```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Or on Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload --port 8000
```

#### Frontend:
```bash
cd frontend
npm install
npm run dev
```

---

## 6. Testing

### 6.1 Backend Pytest & Cross-Tenant Security Verification
```bash
cd backend
pytest -v --tb=short
```
Included test suites:
- Health probe validation (`/health`, `/api/v1/health`)
- User registration & login with constant-time password hashing
- Authentication failures & invalid token handling
- Role restrictions (e.g. `SOC_L1` asset creation denial)
- Tenant-scoped asset creation & event ingestion
- **Dedicated Cross-Tenant Isolation Suite**: Explicitly proves that Tenant A user cannot view, list, or retrieve Tenant B's incidents, assets, events, or alerts.

### 6.2 Frontend Vitest Tests
```bash
cd frontend
npm run test
```

---

## 7. Current Implementation Status (Phase 1)
- [x] Multi-tenant PostgreSQL database models & composite indexes.
- [x] FastAPI async backend with correlation IDs and defense-in-depth headers.
- [x] Constant-time bcrypt hashing & JWT token issue/verification.
- [x] Role-Based Access Control (7 standard SOC roles).
- [x] Tenant-scoped REST APIs for Tenants, Assets, Events, Alerts, and Incidents.
- [x] Immutable audit logging engine.
- [x] Production React + TypeScript SOC dashboard with live telemetry feeds.
- [x] Full Docker Compose setup with health checks.
- [x] CI/CD workflow running Ruff, Pytest, Vitest, and frontend build.
- [x] Comprehensive documentation (`docs/`).

---

## 8. Future Modules & Roadmap (Subsequent Phases)
- **Phase 2: Detection Engineering & Rule Correlation**: SIGMA rule compilation, MITRE ATT&CK mapping, and event stream correlation.
- **Phase 3: Adversary Emulation & Validation**: Strictly lab-contained atomic adversary simulations for defensive posture testing.
- **Phase 4: Evidence-Grounded AI Analysis**: Safe LLM copilot for alert summarization, forensic timeline generation, and proposed response playbooks (with human approval gating).
- **Phase 5: Continuous Security Improvement & GRC**: Automated compliance mapping (SOC2, ISO 27001, NIST CSF) and posture drift remediation.
