# AegisSOC AI — AI Security Architecture

## 1. Core Threat Model & Architectural Principles

Security operations centers processing untrusted adversary signals cannot rely on LLMs as an authorization boundary.
In AegisSOC AI, the AI component is strictly treated as an **advisory intelligence layer**, bounded by immutable system rules:

```
+-------------------------------------------------------------------+
|                     AegisSOC AI Trust Boundary                    |
|                                                                   |
|   +-----------------------+           +-----------------------+   |
|   | Untrusted Telemetry   |           | AI Investigation      |   |
|   | Logs, IPs, Hostnames, | --------> | Layer (Advisory Only) |   |
|   | Usernames, Payloads   |           +-----------------------+   |
|   +-----------------------+                       |               |
|                                                   v               |
|                                       +-----------------------+   |
|                                       | Evidence Validator    |   |
|                                       | (Cryptographic Proof) |   |
|                                       +-----------------------+   |
|                                                   |               |
|                                                   v               |
|                                       +-----------------------+   |
|                                       | Deterministic Risk &  |   |
|                                       | Policy Engine         |   |
|                                       +-----------------------+   |
|                                                   |               |
|                                                   v               |
|   +-----------------------+           +-----------------------+   |
|   | Audit Log             | <-------- | Human Approval Gate   |   |
|   | (Immutable Record)    |           | (Mandatory for SOC)   |   |
|   +-----------------------+           +-----------------------+   |
|                                                   |               |
|                                                   v               |
|                                       +-----------------------+   |
|                                       | Controlled Playbooks  |   |
|                                       | (Mock / Lab Adapters) |   |
|                                       +-----------------------+   |
|                                                   |               |
|                                                   v               |
|                                       +-----------------------+   |
|                                       | Response Verification |   |
|                                       | (State Check)         |   |
|                                       +-----------------------+   |
+-------------------------------------------------------------------+
```

### Invariants:
1. **Never allow LLM -> Direct Security Action**: Under no circumstances can an LLM directly invoke firewall APIs, run shell commands, lock accounts, or delete files.
2. **Never allow LLM Self-Authorization**: The LLM cannot grant approvals or bypass role requirements.
3. **Never Fabricate Evidence**: All claims made by the AI layer must reference legitimate, verifiable database evidence IDs belonging to the tenant.
4. **Never Bypass Tenant Isolation**: All context passed into and findings emitted from the AI layer are strictly partitioned by `tenant_id`.

---

## 2. LLM Provider Abstraction

AegisSOC AI decouples business logic from any specific LLM provider through the `AIProvider` abstract base class defined in [`backend/app/ai/provider.py`](file:///c:/Users/Rahul/OneDrive/Desktop/AegisSOC/backend/app/ai/provider.py):

```python
class AIProvider(ABC):
    @abstractmethod
    async def analyze(self, context: dict[str, Any]) -> AIAnalysisResult: ...

    @abstractmethod
    async def summarize(self, context: dict[str, Any]) -> str: ...

    @abstractmethod
    async def generate_hypotheses(self, context: dict[str, Any]) -> list[AIHypothesis]: ...

    @abstractmethod
    async def recommend_actions(self, context: dict[str, Any]) -> list[AIActionRecommendation]: ...
```

### Providers Supported:
1. **`DeterministicAIProvider`**: Production-grade fallback and test engine. Operates without external API dependencies, executing forensic heuristics, rule correlation parsing, and pattern extraction while enforcing prompt injection isolation.
2. **`ExternalAIProvider`**: Connects via secure HTTPS to enterprise LLM endpoints (OpenAI, Anthropic, or Google Vertex AI).
3. **Mock Provider**: Used in automated unit and regression testing.

If no API key is configured or the upstream LLM service experiences an outage or latency spike, the platform gracefully defaults to `DeterministicAIProvider` without service interruption.

---

## 3. Evidence Grounding Enforcement

To prevent hallucinated evidence:
1. The AI layer receives valid event IDs in its input context.
2. Every output finding or hypothesis emitted by the model is passed through [`backend/app/investigation/evidence_validator.py`](file:///c:/Users/Rahul/OneDrive/Desktop/AegisSOC/backend/app/investigation/evidence_validator.py).
3. If an AI output cites an ID not found in the tenant's database or an ID whose cryptographic SHA-256 hash does not match the database event record:
   - The finding's status is downgraded to `UNKNOWN`.
   - The finding's confidence is clamped to $\le 0.25$.
   - A security warning is logged into the audit trail.
