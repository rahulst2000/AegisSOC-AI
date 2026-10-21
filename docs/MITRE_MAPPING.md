# AegisSOC AI — MITRE ATT&CK Mapping Layer

## 1. Authoritative Architecture

AegisSOC AI maintains a dedicated MITRE ATT&CK mapping layer implemented in `app.detection.mitre_mapper.MitreAttackCatalog`.
The mapping layer enforces strict technical validity:
- **No fabricated IDs**: Every technique ID accepted by the API or compiled from rules must exist in the authoritative catalog.
- **Tactic Resolution**: Tactics are automatically derived from technique mappings to guarantee consistent ontology hierarchy.

---

## 2. Currently Supported Techniques (Phase 2 Baseline)

| Technique ID | Technique Name | Primary Tactic | Detection Use Case |
| :--- | :--- | :--- | :--- |
| **`T1110`** | Brute Force | Credential Access | Baseline repeated auth failure bursts across services |
| **`T1110.001`** | Password Guessing | Credential Access | High-volume single-account SSH credential guessing |
| **`T1110.003`** | Password Spraying | Credential Access | Single IP testing common passwords across distinct users |
| **`T1078`** | Valid Accounts | Defense Evasion, Persistence, Initial Access | Success following repeated failures, anomalous logins |
| **`T1078.003`** | Local Accounts | Defense Evasion, Initial Access | Suspicious interactive login to root or local administrator |
| **`T1059`** | Command and Scripting Interpreter | Execution | Encoded PowerShell, Bash script executions |
| **`T1003`** | OS Credential Dumping | Credential Access | LSASS memory reading, NTDS.dit extraction |
| **`T1046`** | Network Service Discovery | Discovery | Port scans, host enumeration telemetry |

---

## 3. Sigma Tag Translation

Standard Sigma tags are translated automatically by `extract_mitre_from_tags()`:
- `attack.t1110.001` $\rightarrow$ `T1110.001`
- `attack.credential_access` $\rightarrow$ `Credential Access`

Techniques declared in rules undergo validation checks; unrecognized or malformed technique strings (such as `T9999.999`) are rejected by the API with HTTP 422 Unprocessable Entity.

---

## 4. Extensibility

Adding new MITRE ATT&CK techniques requires only registering the entry in `MitreAttackCatalog.TECHNIQUES`:
```python
"T1021.002": {
    "name": "SMB/Windows Admin Shares",
    "tactics": ["Lateral Movement"],
    "description": "Adversaries may use valid accounts to interact with remote shares over SMB.",
}
```
All validation and automated tactic derivation cascades automatically across the detection and correlation pipelines.
