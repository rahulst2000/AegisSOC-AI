# AegisSOC AI — Correlation Engine Architecture

## 1. Overview & Multi-Vector Aggregation

The AegisSOC Correlation Engine bridges isolated detection events into unified, actionable security incidents. Rather than overwhelming analysts with disconnected alerts (e.g. 20 failed SSH logins + 1 successful login + 1 privileged command execution), the engine correlates them across multiple dimensions into a single incident entity.

```
Individual Detections (DetectionResult)
      ↓
Entity Clustering (Source IP, Username, Hostname)
      ↓
Sliding Temporal Window Partitioning (Configurable)
      ↓
Deterministic Risk & Confidence Calculation
      ↓
Unified Incident Creation or Aggregation
      ↓
Forensic Timeline Synthesis (Events + Evidence + Detections)
```

---

## 2. Correlation Dimensions

Correlations are performed along the following dimensions:
1. **Tenant ID**: The ultimate boundary invariant. Detections from different tenants are NEVER correlated.
2. **Source IP Address**: Aggregates repeated attack vectors targeting disparate endpoints from a single adversary host.
3. **Username / Identity**: Tracks account takeover progressions (e.g. brute force -> valid account -> privilege escalation).
4. **Target Hostname / Asset**: Correlates multi-phase attacker behaviors targeting a specific host asset.
5. **MITRE ATT&CK Chain**: Groups tactical progressions across the attack lifecycle.

---

## 3. Configurable Correlation Windows

Correlation windows are strictly decoupled from hardcoded logic and managed via `CorrelationConfig`:

- `BRUTE_FORCE_WINDOW_MINUTES = 5`: Sliding window for rapid authentication bursts.
- `PASSWORD_SPRAY_WINDOW_MINUTES = 10`: Sliding window for multi-user credential spraying from a single IP.
- `FAILURE_THEN_SUCCESS_WINDOW_MINUTES = 10`: Sliding window capturing credential guessing followed by successful ingress.
- `PRIVILEGED_ACCESS_WINDOW_MINUTES = 15`: Temporal correlation for suspicious administrative operations.
- `DEFAULT_CORRELATION_WINDOW_MINUTES = 15`: General entity clustering window.
- `MULTI_STAGE_INCIDENT_WINDOW_MINUTES = 30`: Multi-vector host-level compromise window.

If detections occur outside the specified correlation window, they are cleanly partitioned into distinct temporal incident records.

---

## 4. Deterministic Risk & Confidence Scoring

AegisSOC strictly distinguishes **Risk** (potential security impact) from **Confidence** (evidentiary certainty). Neither score is fabricated.

### Risk Calculation ($0.0 - 100.0$)
- **Base Severity Weight**:
  - `CRITICAL`: 85.0
  - `HIGH`: 70.0
  - `MEDIUM`: 45.0
  - `LOW`: 20.0
- **Attacker Diversity Modifiers**:
  - Technique Count Bonus: $\min(15.0, |\text{unique\_mitre\_techniques}| \times 4.0)$
  - Cross-Asset Bonus: $+5.0$ if multiple distinct assets are affected.
  - Multi-User Identity Bonus: $+5.0$ if multiple user identities are affected.
- **Formula**:
  $$\text{Risk Score} = \min(100.0, \max(0.0, \text{Base} + \text{Bonus}_{\text{techniques}} + \text{Bonus}_{\text{assets}} + \text{Bonus}_{\text{users}}))$$

### Confidence Calculation ($0.0 - 1.0$)
- **Base Rule Confidence**: Arithmetic mean of the underlying detection confidence scores ($\mu_{\text{detection}}$).
- **Forensic Evidence Depth**:
  $$\text{Depth Factor} = \min(1.0, 0.75 + 0.03 \times \min(|\text{evidence\_items}|, 8))$$
- **Formula**:
  $$\text{Confidence Score} = \min(1.0, \max(0.1, \text{round}(0.7 \times \mu_{\text{detection}} + 0.3 \times \text{Depth Factor}, 2)))$$

---

## 5. Idempotent Deduplication

Repeated processing of the identical security event stream or re-evaluating historical detections updates the incident's `last_seen` timestamp and recurrence metrics without spawning redundant duplicate incidents.
