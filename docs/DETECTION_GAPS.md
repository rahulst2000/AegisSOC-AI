# Detection Gap Analysis Engine

The Detection Gap Engine (`app.security_improvement.gap_engine.GapEngine`) analyzes every adversary assessment result to detect failure modes in the defensive pipeline.

---

## 1. Detection Gap Taxonomy

| Gap Type | Description | Severity | Auto-Generated Recommendation |
| :--- | :--- | :--- | :--- |
| `DETECTION_GAP` | Attack telemetry generated, but no detection rule triggered. | **HIGH** | Create or tune threshold-based Sigma detection rule for the technique. |
| `CORRELATION_GAP` | Alert was triggered, but correlation failed to link it into an incident. | **MEDIUM** | Expand correlation window or adjust entity aggregation criteria. |
| `INVESTIGATION_GAP` | Incident created, but autonomous investigation failed. | **MEDIUM** | Verify host telemetry adapters and investigation playbooks. |
| `RESPONSE_GAP` | Incident investigated, but no containment action was recommended. | **HIGH** | Define and map automated containment playbooks for the attack type. |
| `VERIFICATION_GAP` | Containment action executed, but post-action verification failed. | **HIGH** | Review enforcement checks and firewall/identity state verification. |

---

## 2. Evidence Grounding

- Every `SecurityFinding` generated references the specific `assessment_id` and list of `evidence_ids`.
- Gaps are only identified when an empirical execution failure is recorded during an authorized test.
- The engine never invents or simulates unobserved gaps.
