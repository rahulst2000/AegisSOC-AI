# AegisSOC AI — Production AI & Google Gemini Security Architecture

This document specifies the operational security controls, architectural guardrails, secret protection mechanisms, and incident response procedures for integrating Google Gemini as an enterprise AI provider within AegisSOC AI.

---

## 1. Provider Architecture & Pipeline

AegisSOC AI treats large language models strictly as non-authoritative advisory agents. The model can never directly execute containment actions, modify firewall rules, or make state-altering security changes.

### The Immutable Pipeline:

```
Frontend (React/TS)
      ↓ (Encrypted HTTPS)
FastAPI Backend (Authentication + Tenant Scoping)
      ↓
AI Gateway (Provider Dispatcher)
      ↓
Gemini Provider (`GeminiAIProvider`)
      ↓ (Structured JSON output via response_schema)
Structured Output Validation
      ↓
Evidence Validator (Forensic Evidence Grounding & SHA-256 Verification)
      ↓
Risk & Confidence Calculator (Deterministic Formula)
      ↓
Policy Engine (Allowlisted Playbooks & Least Privilege)
      ↓
Human Approval Gate (L1 / L2 Analyst Approval)
      ↓
Response Layer (Deterministic Containment Playbook Execution)
      ↓
Post-Action Verification (State Inspection)
      ↓
Immutable Audit Log (Cryptographically Timestamped)
```

---

## 2. Gemini Environment Configuration

All Gemini configuration is managed via backend environment variables and system secrets. Configuration values must never be checked into version control.

### Required Environment Variables:

| Variable | Description | Default | Security Constraint |
|---|---|---|---|
| `GEMINI_API_KEY` | Google Gemini API Secret Key | *(None - Required for Gemini)* | NEVER commit, log, or expose to frontend |
| `AI_PROVIDER` | Active AI provider (`gemini`, `deterministic`) | `gemini` | Controls provider dispatching |
| `AI_MODEL` | Google Gemini model identifier | `gemini-2.5-flash` | Supported models: `gemini-2.5-flash`, `gemini-1.5-pro` |
| `AI_REQUEST_TIMEOUT_SECONDS` | Maximum timeout for external API calls | `30.0` | Prevents connection hangs |
| `AI_MAX_RETRIES` | Max retry attempts with exponential backoff | `2` | Prevents quota exhaustion storms |
| `AI_MAX_INPUT_CHARS` | Character cap on serialized prompt context | `50000` | Context overflow / DoS protection |
| `AI_MAX_OUTPUT_TOKENS` | Token cap on generated response | `4096` | Cost and output size control |

---

## 3. Secret Protection & Defense-in-Depth

The Gemini API key is a Tier-0 confidential credential. The following protections are enforced:

1. **Source Code & Git**:
   - `backend/.env` is strictly ignored via root `.gitignore` (`.env`, `.env.*`, `!.env.example`).
   - Only `backend/.env.example` is committed, containing placeholders (`your_gemini_api_key_here`).
   - Secret scanners (Gitleaks, Semgrep) run in CI/CD before any commit or PR merge.
2. **Logs & Observability**:
   - `GeminiAIProvider.__repr__` and `__str__` mask all credentials (`api_key_configured=True`).
   - `_sanitize_string()` automatically redacts `AIzaSy...` strings and Bearer tokens before logging.
   - HTTP request headers and authorization strings are excluded from structured logging.
3. **Frontend Bundle Protection**:
   - No `VITE_GEMINI_API_KEY` or `NEXT_PUBLIC_GEMINI_API_KEY` variables exist in the codebase.
   - The frontend never communicates with Google Gemini directly; all requests flow through the AegisSOC backend.
4. **API Responses**:
   - Health and status endpoints (`/api/v1/health/ai`) only report boolean indicators (`api_key_configured: "YES"`) and never print the key, partial characters, or key length.

---

## 4. Deterministic Fallback Mechanism

If the external Gemini service encounters any impediment, AegisSOC AI fails safely and immediately to `DeterministicAIProvider`.

### Fallback Triggers:
- `GEMINI_API_KEY` is missing or empty.
- Network disconnection or DNS resolution failure.
- API request timeout exceeding `AI_REQUEST_TIMEOUT_SECONDS` (30.0s).
- Rate limit exhaustion (HTTP 429) or service unavailability (HTTP 503).
- Structured output parsing failure.

### Guarantees:
- **Zero Fabrication**: The deterministic engine produces findings based purely on matched Sigma detection rules and verified security events.
- **Continuous Operation**: SOC workflows, incident triage, and human approval gates remain 100% operational during cloud outages.

---

## 5. Prompt-Injection & Adversary Payload Quarantining

Attacker-controlled input (event logs, usernames, command lines, HTTP headers, query strings) must never be executed as instructions by the AI.

1. **Untrusted Boundary Tags**:
   - Telemetry context is enclosed inside explicit `<<<UNTRUSTED_SECURITY_TELEMETRY>>>` boundary delimiters.
   - System instructions explicitly command the model to treat all data inside these boundaries as data rather than instructions.
2. **Signature Detection**:
   - `detect_prompt_injection()` scans incoming event payloads for injection signatures (e.g. `ignore previous instructions`, `grant admin`, `system: override`, `drop table`).
   - Detections trigger warning logs and are tagged as adversarial attack evidence.
3. **Strict Structured Output Schemas**:
   - Gemini is constrained to return structured JSON matching `AIAnalysisResult`.
   - Freeform markdown or instruction echo cannot escape the schema fields.

---

## 6. Forensic Evidence Grounding & Hallucination Prevention

AegisSOC AI enforces SHA-256 cryptographic evidence grounding:

1. **Evidence Citation Check**:
   - Every `AIFinding`, `AIHypothesis`, and `AIActionRecommendation` returned by Gemini must cite valid `evidence_ids` corresponding to actual `SecurityEvent` UUIDs in the database.
2. **Automated Downgrading**:
   - If the AI cites a non-existent or fabricated event ID, `validate_and_sanitize_ai_result()` immediately downgrades the finding status to `UNKNOWN` and caps its confidence score at $\le 0.3$.
3. **Action Allowlisting**:
   - Only predefined response actions (`ACCOUNT_LOCKOUT`, `IP_CONTAINMENT`, `SESSION_REVOCATION`, `HOST_ISOLATION`, `L2_ESCALATION`, `COLLECT_EVIDENCE`) are accepted.
   - Arbitrary commands, SQL queries, or unknown action types are dropped.

---

## 7. Multi-Tenant Isolation

Gemini integration preserves strict multi-tenant boundaries:

1. **Pre-Context Scoping**:
   - The backend retrieves security events, detections, and timeline records strictly filtered by `tenant_id == current_user.tenant_id`.
   - Cross-tenant data is never queried or combined.
2. **Post-Generation Evidence Filtering**:
   - Even if an adversary attempts to inject foreign tenant IDs into telemetry, the evidence validation gate validates cited IDs only against the querying tenant's evidence store.
   - Tenant A's investigation can never view or cite Tenant B's data.

---

## 8. Incident Response: API Key Compromise Protocol

If a Gemini API key is suspected of being compromised or accidentally exposed:

1. **Immediate Revocation**:
   - Log into [Google AI Studio](https://aistudio.google.com/) or Google Cloud Console.
   - Immediately delete the compromised API key.
2. **System Fallback Verification**:
   - The backend automatically shifts to `DeterministicAIProvider` without server restart.
3. **Key Rotation**:
   - Generate a new Gemini API key.
   - Update the production secret store / environment variables.
   - Restart the backend worker tasks.
4. **Audit Log Inspection**:
   - Inspect Google Cloud audit logs for anomalous request volumes or unexpected IP origins.
   - Inspect internal AegisSOC audit logs for any unauthorized investigation requests.
