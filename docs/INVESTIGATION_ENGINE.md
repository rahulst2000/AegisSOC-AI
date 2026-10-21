# AegisSOC AI — Investigation Engine

## 1. Overview & Architecture

The AegisSOC AI Investigation Engine is an evidence-grounded, tenant-isolated subsystem designed to conduct automated Tier-1 forensic analysis of correlated security incidents without ever permitting uncontrolled or hallucinated conclusions.

```
Incident Correlated
        ↓
Evidence Collection (Read-Only, Tenant-Scoped)
        ↓
Investigation Context Assembly
        ↓
AI Analysis / Deterministic Heuristic Engine
        ↓
Cryptographic Evidence Validation (SHA-256 & Tenant Scoping)
        ↓
Hypothesis Testing (H1–H8)
        ↓
Confidence Calculation (Deterministic)
        ↓
Response Recommendation & Action Generation
```

### Core Invariant
> **AI recommends. Evidence proves. Policy authorizes. Humans control critical actions. Verification confirms results.**

---

## 2. Investigation Context

The engine accepts `(incident_id, tenant_id)` and securely builds a structured investigation context:
- **Incident Scope**: Severity, status, affected users, affected hosts/assets, external IP indicators, MITRE techniques.
- **Correlated Detections**: Detection rules triggered, rule severity, detection timestamps.
- **Evidence Telemetry**: Normalized events, raw logs, authentication actions, network flows.
- **Historical Context**: Prior related incidents targeting the same assets/identities within the tenant.
- **Asset Enrichment**: Asset criticality, environment (`production`, `staging`, `corporate`), tags.

Tenant isolation is strictly enforced at every query: cross-tenant access attempts immediately fail closed.

---

## 3. Read-Only Evidence Collection Tools

The investigation engine operates using controlled, strictly read-only data access functions defined in [`backend/app/investigation/evidence_collector.py`](file:///c:/Users/Rahul/OneDrive/Desktop/AegisSOC/backend/app/investigation/evidence_collector.py):

| Tool | Purpose | Tenant Scoped |
|---|---|:---:|
| `search_events()` | Filter security events by type, time window, user, or IP | Yes |
| `get_event()` | Retrieve specific event record by ID | Yes |
| `get_authentication_history()` | Query authentication attempts (success/failure) for an identity | Yes |
| `get_user_activity()` | Collect activity timeline for a specific username | Yes |
| `get_host_activity()` | Enumerate network and system actions on a target host | Yes |
| `get_ip_history()` | Inspect historical ingress/egress for an IP address | Yes |
| `get_asset_details()` | Fetch asset posture and criticality level | Yes |
| `get_previous_incidents()` | Correlate with historical incidents for the tenant | Yes |
| `search_related_detections()` | Identify co-occurring or precursor detections | Yes |
| `get_mitre_technique()` | Map attack patterns against MITRE ATT&CK knowledgebase | Static |
| `get_incident_timeline()` | Construct unified chronological sequence of events | Yes |

None of these tools allow raw SQL execution, parameter manipulation across tenant boundaries, or write operations.

---

## 4. Standard Hypothesis Framework (H1–H8)

The engine evaluates eight standard hypotheses for every incident. Hypotheses cannot be marked `CONFIRMED` unless corroborated by immutable, cryptographic evidence.

| Hypothesis ID | Title | Description | Allowed Statuses |
|---|---|---|---|
| **H1** | Credential Attack | Systematic password probing, dictionary, or spray attack | `CONFIRMED`, `LIKELY`, `UNKNOWN`, `DISPROVED` |
| **H2** | Compromised Account | Unauthorized adversary successfully acquired valid account credentials | `CONFIRMED`, `LIKELY`, `UNKNOWN`, `DISPROVED` |
| **H3** | Password Spraying | Low-and-slow horizontal spray across multiple accounts from single IP | `CONFIRMED`, `LIKELY`, `UNKNOWN`, `DISPROVED` |
| **H4** | Brute Force | High-frequency password guessing against a single identity | `CONFIRMED`, `LIKELY`, `UNKNOWN`, `DISPROVED` |
| **H5** | Legitimate Administrative Activity | Authorized administrative maintenance mistakenly flagged as anomalous | `CONFIRMED`, `LIKELY`, `UNKNOWN`, `DISPROVED` |
| **H6** | Potential Lateral Movement | Adversary traversing internal network boundaries across multiple hosts | `CONFIRMED`, `LIKELY`, `UNKNOWN`, `DISPROVED` |
| **H7** | Potential Privilege Escalation | Elevation of user rights from standard to root, admin, or privileged role | `CONFIRMED`, `LIKELY`, `UNKNOWN`, `DISPROVED` |
| **H8** | False Positive | Benign anomaly, scanner noise, or misconfigured legitimate client | `CONFIRMED`, `LIKELY`, `UNKNOWN`, `DISPROVED` |

### Invariant on Uncertainty
When evidence is incomplete, ambiguous, or contradictory, the status **MUST** remain `UNKNOWN`. The system strictly prohibits guessing or fabricating certainty.

---

## 5. Confidence Calculation Formula

Confidence is strictly separated from Risk:
- **Risk (0–100)**: Potential damage or criticality of the compromised assets.
- **Confidence (0.0–1.0)**: Mathematical degree of proof established by tamper-evident telemetry.

Confidence is deterministically calculated by [`backend/app/investigation/confidence.py`](file:///c:/Users/Rahul/OneDrive/Desktop/AegisSOC/backend/app/investigation/confidence.py):

$$\text{Confidence} = \operatorname{clamp}\left(0.1, 0.99, C_{\text{base}} + C_{\text{ev}} + C_{\text{sig}} - P_{\text{contra}} - P_{\text{unknown}}\right)$$

Where:
- $C_{\text{base}}$: Base detection rule confidence (average across triggering detections, typically 0.50–0.70).
- $C_{\text{ev}}$: Evidence volume bonus ($+0.03$ per validated evidence item, capped at $+0.15$).
- $C_{\text{sig}}$: Independent telemetry signal bonus ($+0.05$ per distinct source, e.g. Auth + Network + Host, capped at $+0.15$).
- $P_{\text{contra}}$: Contradictory evidence penalty ($-0.20$ per disproving indicator).
- $P_{\text{unknown}}$: Missing critical telemetry penalty ($-0.10$ if key telemetry is absent).
- **Evidence Downgrade Penalty**: If any cited evidence item fails SHA-256 hash validation or tenant scoping, confidence is clamped to $\le 0.25$.
