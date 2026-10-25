# AegisSOC AI — Engineering Roadmap

## Completed Milestones

### Phase 1 — Foundation & SOC Core (Completed & Verified)
- [x] Multi-tenant PostgreSQL database schema with Alembic migrations
- [x] JWT authentication, role-based access control (RBAC), and session expiration
- [x] Telemetry event ingestion API and schema normalization
- [x] Automatic alerting pipeline and risk scoring engine
- [x] Redis caching, task queue workers, and structured JSON logging
- [x] Security headers and error-handling middleware (zero stacktrace leakage)

### Phase 2 — Detection & Correlation (Completed & Verified)
- [x] Controlled Sigma-compatible rule parser & compiler
- [x] MITRE ATT&CK catalog mapping and technique tagging
- [x] SHA-256 evidence hashing and immutable telemetry verification
- [x] Sliding-window event correlation across IP, user, asset, and time boundaries
- [x] Deterministic risk and confidence calculation
- [x] 10,000-event ingestion & correlation benchmark validation

### Phase 3 — AI Investigation & Policy-Controlled Response (Completed & Verified)
- [x] Automated investigation engine with H1-H8 hypothesis evaluation
- [x] External AI Gateway with Google Gemini 2.5 Flash integration and offline fallback
- [x] Multi-layer prompt injection defense and delimiter boundary isolation
- [x] Anti-hallucination evidence validation (rejection of fabricated event IDs)
- [x] Deterministic response playbooks (IP containment, session revocation, account disable)
- [x] Policy engine with mandatory human-in-the-loop approval gate
- [x] Response verification pipeline (`BEFORE -> ACTION -> AFTER -> VERIFY`)
- [x] L2 escalation package builder with root-cause attribution

### Phase 4 — Adversary Validation & Security Improvement (Completed & Verified)
- [x] Authorized lab adversary simulator (SSH brute force, password spraying, privilege escalation)
- [x] Explicit scope validation with expiry, target allowlists, and strict production rejection
- [x] Detection, correlation, investigation, and verification gap analysis
- [x] Closed-loop remediation lifecycle (`OPEN -> UNDER_REMEDIATION -> RETEST -> VERIFIED`)
- [x] Automated regression test protection and cleanup hooks
- [x] 20 mandatory Phase 4 security and isolation tests

### Phase 5A — Production Deployment Readiness (Completed & Verified)
- [x] Hardened multi-stage Dockerfiles with rootless user execution
- [x] Production Docker Compose architecture with isolated internal network tiers
- [x] Nginx reverse proxy configuration with TLS termination, rate limiting, and strict CSP/HSTS
- [x] Automated database backup script with SHA-256 checksumming (`scripts/backup_db.py`)
- [x] Automated database restore script with tamper verification (`scripts/restore_db.py`)
- [x] End-to-end production smoke test suite (`scripts/production_smoke_test.py`)
- [x] Comprehensive CI/CD workflow with Bandit, pip-audit, Semgrep, Gitleaks, and Trivy

### Phase 5B — Advanced Security Intelligence & Digital Twin (Completed & Verified)
- [x] **5B-01**: Dynamic Security State Model (`SecurityState(t)`) with SHA-256 state hashing
- [x] **5B-02**: Probabilistic Attack Trajectory engine (`NORMAL` -> `CONTAINED`)
- [x] **5B-03**: Tenant-isolated Attack Graph with pathfinding
- [x] **5B-04**: "Why Now?" state transition explanation engine
- [x] **5B-05**: "What Changed?" baseline comparison engine
- [x] **5B-06**: Counterfactual Security Analysis simulation engine (zero production side-effects)
- [x] **5B-07**: Enterprise Digital Twin topology and blast-radius calculator
- [x] **5B-08**: Multi-tenant Organizational Security Memory service
- [x] **5B-09**: Hybrid Threat Intelligence provider abstraction (provider + local telemetry + asset criticality)
- [x] **5B-10**: Continuous Security Improvement candidate loop with human-only approval gate
- [x] **5B-11**: Continuous Adversary Validation scheduler with scope enforcement
- [x] **5B-12**: End-to-end 6-stage MITRE ATT&CK pipeline tracker
- [x] **5B-13**: Auditable GRC Compliance mapping (NIST CSF, ISO 27001, CIS Controls, SOC 2, PCI DSS)
- [x] **5B-14**: Executive Security Posture scorecard across 9 domains
- [x] Unified frontend Security Intelligence dashboard (`frontend/src/pages/IntelligencePage.tsx`)

## Future Research & Long-Term Vision

- [ ] Distributed consensus on multi-cluster security state
- [ ] Hardware Security Module (HSM) signing for evidence hashes
- [ ] eBPF-based real-time telemetry agent integration
- [ ] Decentralized threat intelligence sharing over privacy-preserving cryptographic protocols
