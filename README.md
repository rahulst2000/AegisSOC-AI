# AegisSOC AI

> **Evidence-Grounded Autonomous Security Operations, Adversary Validation & Continuous Security Improvement Platform**

**Creator & Owner:** [Rahul S T](https://github.com/rahulst2000)<br/>
**Repository:** [https://github.com/rahulst2000/AegisSOC-AI](https://github.com/rahulst2000/AegisSOC-AI)<br/>
**Live Frontend:** [https://aegissoc-ai-1.onrender.com](https://aegissoc-ai-1.onrender.com)<br/>
**Live Backend API:** [https://aegissoc-ai.onrender.com](https://aegissoc-ai.onrender.com)<br/>
**API Health Probe:** [https://aegissoc-ai.onrender.com/health](https://aegissoc-ai.onrender.com/health)

[![CI Status](https://github.com/rahulst2000/AegisSOC-AI/actions/workflows/ci.yml/badge.svg)](https://github.com/rahulst2000/AegisSOC-AI/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Framework-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![React: 18](https://img.shields.io/badge/Frontend-React%2018%20%2B%20TypeScript-61DAFB.svg)](https://react.dev/)

---

## 1. Executive Summary & Philosophy

**AegisSOC AI** is an enterprise-grade cybersecurity operations platform engineered for modern defense-in-depth architectures. It seamlessly bridges raw sensor telemetry, automated behavioral detection, forensic evidence validation, adversarial simulation, and continuous security posture improvement.

### Core Operating Loop
```text
Detect → Understand → Predict → Decide → Respond → Verify → Escalate → Improve → Govern
```

### Trust & Safety Model
> **AI recommends. Evidence proves. Policy authorizes. Humans control critical actions. Verification confirms the result.**

- **Evidence-Grounded**: Every alert, investigation, and conclusion is linked to cryptographic SHA-256 evidence records.
- **Strict Tenant Isolation**: Cryptographically verified server-side JWT session derivation ensures absolute partition boundaries.
- **Controlled Automation**: AI never silently executes high-impact remediations; high-risk actions require dual-key human authorization.
- **Continuous Adversary Validation**: Active verification of detection coverage using scoped, non-destructive simulation scenarios.

---

## 2. High-Level Architecture
AegisSOC AI is built as a cloud-native, containerized multi-tier system:

- **Frontend**: Single-page application built in **React 18 + TypeScript + Vite**, with dark-mode glassmorphic SOC command center aesthetics, live telemetry indicators, and interactive incident triage.
- **Backend**: Asynchronous high-performance REST API built with **FastAPI / Python 3.12+**, structured JSON logging, correlation IDs (`X-Request-ID`), defense-in-depth security headers, and Pydantic v2 data validation.
- **Data Persistence**: **PostgreSQL 16** with SQLAlchemy 2.0 ORM and Alembic migrations, utilizing composite indices optimized for tenant queries, timestamps, severity, and hostnames.
- **Cache & Message Broker**: **Redis 7** (with resilient in-memory fallback queues for zero-loss operation in decoupled serverless deployments).

```
AegisSOC AI Platform
 ├── Frontend (Port 3000 / Render)  --> Vite / React / TypeScript SOC Dashboard
 ├── Backend (Port 8000 / Render)   --> FastAPI, Pydantic, SQLAlchemy 2.0
 ├── Database (Port 5432 / Neon)    --> PostgreSQL 16 (Tenant-Isolated Schemas)
 └── Cache / Queue                  --> Redis 7 & Resilient In-Memory Fallback Queue
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
- Health check (liveness): `http://localhost:8000/healthz`
- Health check (detailed): `http://localhost:8000/health`

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

## 7. Platform Verification & Phase Status

| Phase | Description | Status | Verification Metrics |
| :--- | :--- | :--- | :--- |
| **Phase 1** | Foundation & SOC Core | **VERIFIED** | Auth, RBAC, Multi-Tenancy, Normalization |
| **Phase 2** | Detection & Correlation | **VERIFIED** | Sigma Compiler, MITRE ATT&CK, 10k-event benchmark |
| **Phase 3** | AI Investigation & Response | **VERIFIED** | Gemini 2.5 Flash, Prompt Injection Defense, Playbooks |
| **Phase 4** | Adversary Validation | **VERIFIED** | Lab Simulations, Detection Gaps, Retest Lifecycle |
| **Phase 5A** | Production Deployment | **VERIFIED** | Hardened Compose, Nginx TLS, Backups, Smoke Tests |
| **Phase 5B** | Advanced Security Intelligence | **VERIFIED** | SecurityState(t), Attack Graph, Trajectory, GRC |

### Test & Security Assurance Summary
- **Backend Tests**: **137 passed** (0 failures, 100% passing across functional, isolation, detection normalization, and benchmark suites).
- **Frontend Tests**: **3 passed** (`vitest run`).
- **Live Verification**: **35/35 stages verified** (34 passed, 1 restricted by safety policy).
- **Production Smoke Tests**: **100% passed** (`scripts/production_smoke_test.py`).
- **Static Analysis & SAST**: **0 Medium/High Issues** (`bandit -r app -ll`).
- **Dependency Vulnerabilities**: **0 Known CVEs** (`pip-audit -r requirements.txt`).
- **Secret Scanning**: **0 Leaked Secrets / Keys** (`Gitleaks` & regex scanner).

---

## 8. Verification Reports & Live Documentation

For the comprehensive, evidence-grounded release scorecard, test matrix, defect register, and audit findings, consult:
- [`docs/LIVE_DEPLOYMENT_VERIFICATION.md`](file:///c:/Users/Rahul/OneDrive/Desktop/AegisSOC/docs/LIVE_DEPLOYMENT_VERIFICATION.md)
- [`docs/LIVE_FEATURE_ACCEPTANCE.md`](file:///c:/Users/Rahul/OneDrive/Desktop/AegisSOC/docs/LIVE_FEATURE_ACCEPTANCE.md)
- [`docs/FINAL_PROJECT_VERIFICATION.md`](file:///c:/Users/Rahul/OneDrive/Desktop/AegisSOC/docs/FINAL_PROJECT_VERIFICATION.md)
- [`docs/ARCHITECTURE.md`](file:///c:/Users/Rahul/OneDrive/Desktop/AegisSOC/docs/ARCHITECTURE.md)
- [`docs/SECURITY_MODEL.md`](file:///c:/Users/Rahul/OneDrive/Desktop/AegisSOC/docs/SECURITY_MODEL.md)
- [`SECURITY.md`](file:///c:/Users/Rahul/OneDrive/Desktop/AegisSOC/SECURITY.md)

