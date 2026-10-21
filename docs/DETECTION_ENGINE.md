# AegisSOC AI — Detection Engine Architecture

## 1. Overview & Pipeline

The AegisSOC Detection Engine evaluates incoming normalized security telemetry against compiled Sigma-compatible detection rules in a strictly isolated, multi-tenant environment. Detections are backed by forensically validated evidence and mapped directly to authoritative MITRE ATT&CK techniques.

```
Security Events
      ↓
Detection Rules (Global + Tenant Scoped)
      ↓
Safe AST Rule Evaluation (No eval())
      ↓
Detection Match & Deduplication Hash Check
      ↓
Verifiable Evidence Collection (SHA-256)
      ↓
MITRE ATT&CK Mapping
      ↓
Alert & Asynchronous Queue Dispatch
      ↓
Incident Correlation
```

---

## 2. Detection Rule Representation

Detection rules in AegisSOC represent structured, immutable data specifications:

- `rule_id`: Unique identifier (e.g. `AEGIS-SIG-SSH-BRUTEFORCE`).
- `tenant_id`: `NULL` for global system baseline rules; populated with Tenant UUID for custom rules.
- `name`: Human-readable threat title.
- `description`: Forensic rationale and attack behavior indicators.
- `version`: Rule semantic version string.
- `enabled`: Boolean toggle for rule activation.
- `severity`: Standard classification (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `confidence`: Calibrated evidentiary confidence score ($0.1$ to $1.0$).
- `event_types`: Targeted normalized event categories.
- `conditions`: Structured AST condition mapping (selections, filters, timeframes, aggregations).
- `mitre_tactics`: Attributed MITRE tactics (e.g., `Credential Access`).
- `mitre_techniques`: Attributed technique IDs (e.g., `T1110`, `T1110.001`).
- `tags`: Operational metadata and category labels.

---

## 3. Safe Evaluation (Zero `eval()`)

AegisSOC enforces strict defensive guidelines: **detection rules are data, not code**.

- The `RuleEvaluator` parses compiled AST selection dictionaries against `SecurityEvent` attributes and normalized payloads.
- Modifiers supported:
  - Exact match (case-insensitive string equality).
  - List matching (logical OR across array entries).
  - `contains`: Substring inclusion.
  - `startswith`: Prefix matching.
  - `endswith`: Suffix matching.
  - `re`: Controlled safe regular expression evaluation with error boundary handling.
- **Zero dynamic code execution**: No `eval()`, `exec()`, or unpickling is permitted.

---

## 4. Multi-Tenant Isolation

- Global system baseline rules are visible and evaluated for all tenants.
- Tenant-specific rules are only visible, editable, and evaluated within that tenant partition.
- Detections and underlying evidence strictly inherit the originating event's `tenant_id`.
- The engine guarantees invariant boundary checking: events from differing tenants will immediately trigger a hard isolation fault if mixed.

---

## 5. False Positive Management

Every `DetectionResult` includes telemetry fields for ongoing operational tuning:
- `detection_count`: Number of times the detection triggered.
- `previous_occurrences`: Historical occurrence count for this rule in the tenant.
- `false_positive_status`: `UNREVIEWED`, `CONFIRMED_TRUE_POSITIVE`, `FALSE_POSITIVE`, `BENIGN_KNOWN`.
- `analyst_feedback`: Structured metadata, review notes, and analyst attributions.

---

## 6. Deduplication & Idempotency

When processing high-frequency event streams, repetitive duplicate alerts are prevented using a deterministic cryptographic SHA-256 hash:

$$\text{dedup\_hash} = \text{SHA256}(\text{tenant\_id} : \text{rule\_id} : \text{sorted}(\text{event\_ids}))$$

If a detection with an identical hash already exists in the tenant's partition, the engine increments the occurrence counter without generating spurious duplicate alerts or incidents.
