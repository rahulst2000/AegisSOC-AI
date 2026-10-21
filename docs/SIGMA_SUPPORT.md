# AegisSOC AI — Sigma Rule Support & Specification

## 1. Supported Sigma Feature Scope

AegisSOC AI implements a controlled, memory-safe Sigma rule compilation and evaluation layer. It compiles standard Sigma rule specifications directly into an internal Abstract Syntax Tree (AST) for real-time stream evaluation.

### Supported Fields
- `title`: Human-readable name.
- `id`: Unique rule identifier (e.g. `AEGIS-SIG-SSH-BRUTEFORCE`).
- `status`: Rule maturity (`stable`, `test`, `experimental`).
- `description`: Detailed technical explanation.
- `version`: Version string.
- `logsource`: Category (`authentication`, `process_creation`) and service (`ssh`, `ldap`, `windows`).
- `detection`:
  - `selection`: Field-to-value matching criteria.
  - `filter`: Exclusion criteria (events matching any filter are discarded).
  - `timeframe`: Sliding temporal window (`5m`, `10m`, `1h`, `24h`).
  - `condition`: Logical execution expression (e.g., `selection`, `selection and not filter`, aggregation pipes).
- `level`: Severity mapping (`low`, `medium`, `high`, `critical`).
- `tags`: Standard MITRE ATT&CK tags (`attack.credential_access`, `attack.t1110.001`).

---

## 2. Supported Modifiers

Field modifiers allow fine-grained matching without code execution:

| Modifier | Semantics | Example |
| :--- | :--- | :--- |
| *(default)* | Case-insensitive exact match | `event_type: AUTH_FAILURE` |
| `list` | Logical OR across array of candidates | `username: [root, admin, administrator]` |
| `contains` | Substring inclusion check | `CommandLine\|contains: -enc` |
| `startswith` | String prefix check | `Path\|startswith: /etc/` |
| `endswith` | String suffix check | `Image\|endswith: powershell.exe` |
| `re` | Safe regex search with error handling | `source_ip\|re: ^192\.168\.\d+\.\d+$` |

---

## 3. Supported Aggregations

AegisSOC supports sliding-window aggregations via condition pipe syntax:

1. **Volume Burst**:
   ```yaml
   condition: selection | count() > 9
   ```
   Triggers when count of matched events exceeds the threshold within the specified `timeframe`.

2. **Entity Grouping & Cardinality**:
   ```yaml
   condition: selection | count(username) by source_ip > 4
   ```
   Triggers when distinct values of a target field (e.g., unique `username`s) grouped by an entity (`source_ip`) exceed the threshold within the `timeframe`.

---

## 4. Built-in Sigma Rules

Stored in `detection_rules/`:

1. `ssh_bruteforce.yml`: 10 failed SSH logins from single IP within 5 minutes (`T1110.001`).
2. `password_spraying.yml`: 5 distinct usernames failing from single IP within 10 minutes (`T1110.003`).
3. `failure_then_success.yml`: Repeated failures followed by successful login within 10 minutes (`T1078`).
4. `invalid_user.yml`: Login attempts targeting invalid / non-existent user accounts (`T1110`).
5. `privileged_login.yml`: Successful login to high-privilege administrative accounts (`T1078.003`).
6. `multiple_failures_single_ip.yml`: Multi-service failure burst from single source IP (`T1110`).

---

## 5. Explicit Limitations

- **Not supported yet**:
  - Raw Lucene / Elasticsearch search strings.
  - Multi-line complex nested parentheses boolean logic beyond `selection and not filter`.
  - Non-standard Sigma backends or field mapping transforms.
  - Arbitrary Python code in rules (strictly forbidden).
- **Security Boundaries**:
  - Maximum rule file size: 1 MB.
  - Strict PyYAML `SafeLoader` only; no object instantiation.
