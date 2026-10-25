# Security Policy — AegisSOC AI

AegisSOC AI is an autonomous, evidence-grounded Security Operations Center platform with strict human-in-the-loop policy control, tenant isolation, and cryptographic auditability.

## 1. Security Architecture & Invariants

AegisSOC AI enforces non-negotiable architectural principles:
1. **Advisory AI Only**: Large Language Models and AI agents have **zero** executive authority over security actions. AI outputs are strictly treated as non-authoritative recommendations requiring human review.
2. **Deterministic Response Verification**: Security actions transition through `BEFORE -> ACTION -> AFTER -> VERIFY`. No action is considered verified without deterministic evidence verification.
3. **Tenant Isolation**: All database queries, caches, vector spaces, and AI contexts enforce strong tenant isolation with SQL-level enforcement. Cross-tenant leakage is categorically prohibited.
4. **Human Policy Gate**: Automated production rule changes, adversary simulation authorizations, and containment responses mandate human approvals with strict RBAC (`SOC_L2`, `SECURITY_ENGINEER`, `TENANT_ADMIN`).
5. **No Production Offense**: Adversary simulation tools strictly reject production IP addresses, hostnames, and environments. Simulation is only permissible within authorized lab scopes.
6. **Defense in Depth**: Container rootless execution, JWT HMAC-SHA256 signature verification, CSP headers, rate-limiting zones, and strict parameter validation across all endpoints.

## 2. Threat Modeling & AI Safety

- **Prompt Injection Defense**: All untrusted telemetry payloads, event headers, and raw logs undergo multi-stage sanitization, instruction stripping, and delimiter isolation before ingestion into LLM prompt contexts.
- **Evidence Verification**: The AI engine is validated against synthetic hallucination; recommendations referencing fabricated or cross-tenant event IDs are rejected and trigger fallback to deterministic analysis.
- **API Key Secrecy**: External credentials (such as Google Gemini API keys) are stored in secure environment secrets, never exposed to clients, never logged, and redacted from telemetry.

## 3. Supported Versions

| Version | Status | Security Updates |
| :--- | :--- | :--- |
| `1.0.0` (Production Candidate) | Release Candidate | Supported |

## 4. Reporting a Vulnerability

If you discover a security vulnerability in AegisSOC AI:
1. **Do not disclose publicly.** Avoid creating public GitHub issues for security vulnerabilities.
2. Email the core security team at `security@aegissoc.io` with details including:
   - Description of the vulnerability and attack vector.
   - Proof of Concept (PoC) or reproducible test case within an isolated lab environment.
   - Potential impact on tenant isolation or policy enforcement.
3. You will receive an acknowledgment within 24 hours and regular status updates until remediation is verified.
