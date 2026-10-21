import abc
import os
from typing import Any

from app.ai.schemas import AIActionRecommendation, AIAnalysisResult, AIFinding, AIHypothesis
from app.ai.validator import detect_prompt_injection, validate_and_sanitize_ai_result


class AIProvider(abc.ABC):
    """Abstract base class for evidence-grounded AI investigation providers."""

    @abc.abstractmethod
    async def analyze(self, context: dict[str, Any]) -> AIAnalysisResult:
        """Analyzes incident context and returns a complete structured investigation result."""
        pass

    @abc.abstractmethod
    async def summarize(self, context: dict[str, Any]) -> str:
        """Generates an evidence-grounded executive summary."""
        pass

    @abc.abstractmethod
    async def generate_hypotheses(self, context: dict[str, Any]) -> list[AIHypothesis]:
        """Evaluates investigation hypotheses against available evidence."""
        pass

    @abc.abstractmethod
    async def recommend_actions(self, context: dict[str, Any]) -> list[AIActionRecommendation]:
        """Recommends controlled response actions subject to policy and human approval."""
        pass


class DeterministicAIProvider(AIProvider):
    """
    Deterministic rule-based AI investigation provider.
    Guarantees evidence grounding, deterministic repeatability, offline capability,
    and resilience against prompt injection. Used as default and fallback provider.
    """

    async def analyze(self, context: dict[str, Any]) -> AIAnalysisResult:
        events = context.get("events", [])
        detections = context.get("detections", [])
        incident = context.get("incident", {})
        valid_event_ids = {str(e.get("id")) for e in events if e.get("id")}

        # 1. Scan for prompt injection across all event text
        injections_found: list[dict[str, Any]] = []
        for e in events:
            raw_text = str(e.get("raw_payload", "")) + " " + str(e.get("normalized_event", ""))
            detected = detect_prompt_injection(raw_text)
            if detected:
                injections_found.append(
                    {
                        "event_id": str(e.get("id")),
                        "patterns": detected,
                    }
                )

        # 2. Extract key metrics
        source_ips = incident.get("source_ips", [])
        usernames = incident.get("affected_users", [])
        hostnames = incident.get("affected_assets", [])
        mitre_techs = set(incident.get("mitre_techniques", []))
        for d in detections:
            mitre_techs.update(d.get("mitre_techniques", []))

        # Check for attack patterns
        has_bruteforce = (
            "T1110.001" in mitre_techs
            or any("BRUTEFORCE" in str(d.get("rule_id", "")).upper() for d in detections)
            or sum(1 for e in events if "fail" in str(e.get("event_type", "")).lower()) >= 4
        )
        has_spraying = "T1110.003" in mitre_techs or any(
            "SPRAYING" in str(d.get("rule_id", "")).upper() for d in detections
        )
        has_valid_accounts = (
            "T1078" in mitre_techs
            or "T1078.003" in mitre_techs
            or any("SUCCESS" in str(d.get("rule_id", "")).upper() for d in detections)
            or any("success" in str(e.get("event_type", "")).lower() for e in events)
        )
        has_failures = (
            any("FAIL" in str(d.get("rule_id", "")).upper() for d in detections)
            or has_bruteforce
            or any("fail" in str(e.get("event_type", "")).lower() for e in events)
        )

        findings: list[AIFinding] = []
        known_facts: list[str] = []
        unknowns: list[str] = []
        attack_chain: list[str] = []

        if injections_found:
            inj_eids = [i["event_id"] for i in injections_found]
            findings.append(
                AIFinding(
                    finding="Adversarial prompt injection attempt detected inside security event payloads.",
                    status="CONFIRMED",
                    evidence_ids=inj_eids,
                    confidence=1.0,
                    reasoning_summary=(
                        "Security event content contained override instructions intended to subvert AI analysis."
                    ),
                )
            )
            known_facts.append(
                f"Prompt injection patterns detected in {len(injections_found)} event(s). Instructions ignored."
            )

        if has_bruteforce and source_ips:
            bf_eids = [str(e.get("id")) for e in events if e.get("id")][:10]
            ip_str = ", ".join(source_ips)
            findings.append(
                AIFinding(
                    finding=f"High-frequency authentication guessing detected originating from source IP(s): {ip_str}.",
                    status="CONFIRMED",
                    evidence_ids=bf_eids,
                    confidence=0.95,
                    reasoning_summary=(
                        "Repeated credential failures matched MITRE T1110.001 within configured correlation window."
                    ),
                )
            )
            attack_chain.append(f"Credential Guessing: Adversary probed accounts from {ip_str}")
            known_facts.append(f"Source IP(s) {ip_str} initiated brute-force authentication sequence.")

        if has_spraying:
            spray_eids = [str(e.get("id")) for e in events if e.get("id")][:10]
            u_str = ", ".join(usernames)
            findings.append(
                AIFinding(
                    finding=f"Horizontal password spraying detected across multiple identities: {u_str}.",
                    status="CONFIRMED",
                    evidence_ids=spray_eids,
                    confidence=0.92,
                    reasoning_summary="Multiple user accounts targeted from single origin matching MITRE T1110.003.",
                )
            )
            attack_chain.append(f"Password Spraying: Horizontal credential spraying across {len(usernames)} identities")
            known_facts.append("Multiple distinct accounts targeted with credential spray pattern.")

        if has_failures and has_valid_accounts:
            combo_eids = [str(e.get("id")) for e in events if e.get("id")]
            findings.append(
                AIFinding(
                    finding=(
                        "Authentication failure burst followed by successful "
                        "authentication indicating compromised account."
                    ),
                    status="CONFIRMED" if len(events) >= 4 else "LIKELY",
                    evidence_ids=combo_eids[:10],
                    confidence=0.88,
                    reasoning_summary=(
                        "Chronological transition from repeated authentication failures to valid session establishment."
                    ),
                )
            )
            attack_chain.append(f"Account Compromise: Valid session established on account(s) {', '.join(usernames)}")
            known_facts.append(
                f"Account(s) {', '.join(usernames)} successfully authenticated following failure sequence."
            )
        elif not has_failures and has_valid_accounts:
            # Single normal successful login
            succ_eids = [str(e.get("id")) for e in events if e.get("id")]
            findings.append(
                AIFinding(
                    finding="Standard single successful authentication observed with no preceding failure anomalies.",
                    status="CONFIRMED",
                    evidence_ids=succ_eids,
                    confidence=0.85,
                    reasoning_summary="Single isolated login without credential guessing or anomalous frequency.",
                )
            )
            known_facts.append("Authentication occurred without preceding brute force or spray activity.")

        if not events:
            unknowns.append("No security event evidence records linked to incident.")

        # Unknowns check
        if usernames and "UNKNOWN" in [u.upper() for u in usernames]:
            unknowns.append("Target username in some events could not be resolved.")
        if not source_ips:
            unknowns.append("Adversary source IP address could not be definitively determined.")

        # 3. Evaluate Hypotheses H1 - H8
        hypotheses = await self.generate_hypotheses(context)

        # 4. Generate Recommendations
        recommendations = await self.recommend_actions(context)

        # 5. Executive summary and L1/L2 decision
        if has_bruteforce and has_valid_accounts:
            exec_summary = (
                f"High-confidence credential compromise detected. Attacker at {', '.join(source_ips) or 'unknown IP'} "
                f"conducted credential attacks before establishing an authenticated session as {', '.join(usernames)}."
            )
            l1_decision = "CONTAIN_AND_ESCALATE"
            l2_escalation_recommended = True
        elif has_bruteforce or has_spraying:
            exec_summary = (
                f"Credential access campaign in progress. Source IP(s) {', '.join(source_ips) or 'unknown'} "
                f"targeting {len(usernames)} account(s). No successful unauthorized session identified yet."
            )
            l1_decision = "CONTAIN_SOURCE_IP"
            l2_escalation_recommended = False
        elif not has_failures and has_valid_accounts:
            exec_summary = "Routine authentication activity. No malicious credential abuse identified."
            l1_decision = "NO_ACTION_REQUIRED"
            l2_escalation_recommended = False
        else:
            exec_summary = "Anomalous security activity under investigation. Evidence is being correlated."
            l1_decision = "COLLECT_MORE_EVIDENCE"
            l2_escalation_recommended = len(hostnames) > 1

        rec_next_steps = [
            "Review verified forensic evidence records attached to this incident.",
            "Verify whether source IP belongs to known VPN, cloud exit, or internal proxy.",
            "Validate user MFA logs for corresponding authentication timestamps.",
        ]

        raw_result = AIAnalysisResult(
            executive_summary=exec_summary,
            attack_chain=attack_chain,
            findings=findings,
            hypotheses=hypotheses,
            recommendations=recommendations,
            known_facts=known_facts,
            unknowns=unknowns,
            recommended_next_steps=rec_next_steps,
            l1_decision=l1_decision,
            l2_escalation_recommended=l2_escalation_recommended,
        )

        return validate_and_sanitize_ai_result(raw_result, valid_event_ids)

    async def summarize(self, context: dict[str, Any]) -> str:
        analysis = await self.analyze(context)
        return analysis.executive_summary

    async def generate_hypotheses(self, context: dict[str, Any]) -> list[AIHypothesis]:
        events = context.get("events", [])
        detections = context.get("detections", [])
        incident = context.get("incident", {})
        all_eids = [str(e.get("id")) for e in events if e.get("id")]
        mitre_techs = set(incident.get("mitre_techniques", []))
        for d in detections:
            mitre_techs.update(d.get("mitre_techniques", []))

        has_bruteforce = (
            "T1110.001" in mitre_techs
            or any("BRUTEFORCE" in str(d.get("rule_id", "")).upper() for d in detections)
            or sum(1 for e in events if "fail" in str(e.get("event_type", "")).lower()) >= 4
        )
        has_spraying = "T1110.003" in mitre_techs or any(
            "SPRAYING" in str(d.get("rule_id", "")).upper() for d in detections
        )
        has_success = (
            "T1078" in mitre_techs
            or any("SUCCESS" in str(d.get("rule_id", "")).upper() for d in detections)
            or any("success" in str(e.get("event_type", "")).lower() for e in events)
        )
        has_priv = "T1078.003" in mitre_techs or any(
            "PRIVILEGED" in str(d.get("rule_id", "")).upper() for d in detections
        )
        has_failures = (
            has_bruteforce
            or any("FAIL" in str(d.get("rule_id", "")).upper() for d in detections)
            or any("fail" in str(e.get("event_type", "")).lower() for e in events)
        )

        hypotheses: list[AIHypothesis] = []

        # H1: Credential Attack
        h1_status = "CONFIRMED" if (has_bruteforce or has_spraying) and all_eids else "UNKNOWN"
        hypotheses.append(
            AIHypothesis(
                hypothesis_id="H1",
                title="Credential Attack",
                description="Adversary is conducting systematic credential probing or dictionary attacks.",
                status=h1_status,
                confidence=0.95 if h1_status == "CONFIRMED" else 0.1,
                evidence_ids=all_eids[:10] if h1_status == "CONFIRMED" else [],
                supporting_evidence=["Repeated authentication failures matching brute-force signatures"]
                if h1_status == "CONFIRMED"
                else [],
                contradicting_evidence=[]
                if h1_status == "CONFIRMED"
                else ["No authentication failure bursts detected"],
                unknowns=[] if all_eids else ["Insufficient authentication telemetry"],
            )
        )

        # H2: Compromised Account
        if (has_bruteforce or has_spraying or has_failures) and has_success and all_eids:
            h2_status = "CONFIRMED" if len(all_eids) >= 4 else "LIKELY"
            h2_conf = 0.90 if h2_status == "CONFIRMED" else 0.75
            h2_sup = ["Failures followed immediately by successful authentication session"]
        elif not has_failures and not has_bruteforce and has_success:
            h2_status = "DISPROVED"
            h2_conf = 0.80
            h2_sup = []
        else:
            h2_status = "UNKNOWN"
            h2_conf = 0.1
            h2_sup = []

        hypotheses.append(
            AIHypothesis(
                hypothesis_id="H2",
                title="Compromised Account",
                description="An unauthorized adversary successfully acquired and leveraged valid account credentials.",
                status=h2_status,
                confidence=h2_conf,
                evidence_ids=all_eids[:10] if h2_status in ("CONFIRMED", "LIKELY") else [],
                supporting_evidence=h2_sup,
                contradicting_evidence=["No successful logins observed"] if not has_success else [],
                unknowns=[]
                if h2_status in ("CONFIRMED", "LIKELY", "DISPROVED")
                else ["Post-authentication user behavior telemetry missing"],
            )
        )

        # H3: Password Spraying
        h3_status = "CONFIRMED" if has_spraying and all_eids else "UNKNOWN"
        hypotheses.append(
            AIHypothesis(
                hypothesis_id="H3",
                title="Password Spraying",
                description="Low-and-slow horizontal password spray targeting diverse accounts from a single IP.",
                status=h3_status,
                confidence=0.92 if h3_status == "CONFIRMED" else 0.1,
                evidence_ids=all_eids[:10] if h3_status == "CONFIRMED" else [],
                supporting_evidence=["Single source IP targeted multiple unique usernames"]
                if h3_status == "CONFIRMED"
                else [],
                contradicting_evidence=[] if h3_status == "CONFIRMED" else ["Attempts focused on single user identity"],
                unknowns=[],
            )
        )

        # H4: Brute Force
        h4_status = (
            "CONFIRMED"
            if has_bruteforce and not has_spraying and all_eids
            else ("LIKELY" if has_bruteforce else "UNKNOWN")
        )
        hypotheses.append(
            AIHypothesis(
                hypothesis_id="H4",
                title="Brute Force",
                description="High-frequency password guessing directed at a single target account.",
                status=h4_status,
                confidence=0.94 if h4_status == "CONFIRMED" else (0.80 if h4_status == "LIKELY" else 0.1),
                evidence_ids=all_eids[:10] if h4_status in ("CONFIRMED", "LIKELY") else [],
                supporting_evidence=["High rate of authentication failures for single user"]
                if h4_status in ("CONFIRMED", "LIKELY")
                else [],
                contradicting_evidence=[]
                if h4_status in ("CONFIRMED", "LIKELY")
                else ["No high-frequency failure cluster observed"],
                unknowns=[],
            )
        )

        # H5: Legitimate Administrative Activity
        if not has_failures and not has_bruteforce and not has_spraying and has_success:
            h5_status = "LIKELY"
            h5_conf = 0.85
            h5_sup = ["Isolated successful login without preceding failure anomalies"]
        elif (has_bruteforce or has_failures) and has_success:
            h5_status = "DISPROVED"
            h5_conf = 0.88
            h5_sup = []
        else:
            h5_status = "UNKNOWN"
            h5_conf = 0.2
            h5_sup = []

        hypotheses.append(
            AIHypothesis(
                hypothesis_id="H5",
                title="Legitimate Administrative Activity",
                description="Routine, authorized user or administrator operation mistaken for malicious behavior.",
                status=h5_status,
                confidence=h5_conf,
                evidence_ids=all_eids[:5] if h5_status == "LIKELY" else [],
                supporting_evidence=h5_sup,
                contradicting_evidence=["Preceding credential guessing sequence contradicts routine access"]
                if h5_status == "DISPROVED"
                else [],
                unknowns=["Change management ticket validation pending"],
            )
        )

        # H6: Potential Lateral Movement
        affected_hosts = incident.get("affected_assets", [])
        h6_status = "LIKELY" if len(affected_hosts) > 1 and has_success else "UNKNOWN"
        hypotheses.append(
            AIHypothesis(
                hypothesis_id="H6",
                title="Potential Lateral Movement",
                description="Adversary traversing from one compromised host to additional internal systems.",
                status=h6_status,
                confidence=0.70 if h6_status == "LIKELY" else 0.1,
                evidence_ids=all_eids[:5] if h6_status == "LIKELY" else [],
                supporting_evidence=[f"Multiple internal hosts involved: {', '.join(affected_hosts)}"]
                if h6_status == "LIKELY"
                else [],
                contradicting_evidence=["Activity isolated to a single endpoint"] if len(affected_hosts) <= 1 else [],
                unknowns=["Internal network flow logs across internal segments"],
            )
        )

        # H7: Potential Privilege Escalation
        h7_status = (
            "CONFIRMED"
            if has_priv and all_eids
            else (
                "LIKELY"
                if has_success
                and any(u in ("root", "admin", "administrator") for u in incident.get("affected_users", []))
                else "UNKNOWN"
            )
        )
        hypotheses.append(
            AIHypothesis(
                hypothesis_id="H7",
                title="Potential Privilege Escalation",
                description="Adversary elevated permissions to administrative or superuser privileges.",
                status=h7_status,
                confidence=0.90 if h7_status == "CONFIRMED" else (0.75 if h7_status == "LIKELY" else 0.1),
                evidence_ids=all_eids[:5] if h7_status in ("CONFIRMED", "LIKELY") else [],
                supporting_evidence=["Privileged account (root/admin) accessed"]
                if h7_status in ("CONFIRMED", "LIKELY")
                else [],
                contradicting_evidence=[]
                if h7_status in ("CONFIRMED", "LIKELY")
                else ["Standard non-privileged account scope"],
                unknowns=[],
            )
        )

        # H8: False Positive
        if not has_bruteforce and not has_spraying and not has_priv and has_success:
            h8_status = "LIKELY"
            h8_conf = 0.80
        elif has_bruteforce or (has_failures and has_success):
            h8_status = "DISPROVED"
            h8_conf = 0.90
        else:
            h8_status = "UNKNOWN"
            h8_conf = 0.2

        hypotheses.append(
            AIHypothesis(
                hypothesis_id="H8",
                title="False Positive",
                description="Detection triggered by misconfiguration, scheduled script, or benign user mistake.",
                status=h8_status,
                confidence=h8_conf,
                evidence_ids=all_eids[:5] if h8_status == "LIKELY" else [],
                supporting_evidence=["Single successful login with standard profile"] if h8_status == "LIKELY" else [],
                contradicting_evidence=["Multi-signal credential guessing sequence confirmed"]
                if h8_status == "DISPROVED"
                else [],
                unknowns=["Baseline user typical login time and geo-IP correlation"],
            )
        )

        return hypotheses

    async def recommend_actions(self, context: dict[str, Any]) -> list[AIActionRecommendation]:
        events = context.get("events", [])
        incident = context.get("incident", {})
        detections = context.get("detections", [])
        all_eids = [str(e.get("id")) for e in events if e.get("id")]
        source_ips = incident.get("source_ips", [])
        usernames = [u for u in incident.get("affected_users", []) if u and u.lower() not in ("unknown", "none")]
        hostnames = incident.get("affected_assets", [])
        mitre_techs = set(incident.get("mitre_techniques", []))
        for d in detections:
            mitre_techs.update(d.get("mitre_techniques", []))

        recs: list[AIActionRecommendation] = []

        # 1. IP Containment recommendation
        for ip in source_ips:
            if ip and not ip.startswith("127.") and ip != "::1":
                recs.append(
                    AIActionRecommendation(
                        action_type="IP_CONTAINMENT",
                        target_entity=ip,
                        target_type="IP",
                        playbook_id="PLAYBOOK-002",
                        reason=f"Block malicious source IP {ip} responsible for credential guessing attack.",
                        risk_score=incident.get("risk_score", 70),
                        confidence=incident.get("confidence_score", 0.9),
                        evidence_ids=all_eids[:5],
                    )
                )

        # 2. Account Lockout / Session Revocation
        has_success = "T1078" in mitre_techs or any("SUCCESS" in str(d.get("rule_id", "")) for d in detections)
        for user in usernames:
            if has_success:
                recs.append(
                    AIActionRecommendation(
                        action_type="SESSION_REVOCATION",
                        target_entity=user,
                        target_type="USER",
                        playbook_id="PLAYBOOK-003",
                        reason=f"Revoke active tokens and sessions for compromised account '{user}'.",
                        risk_score=min(100, incident.get("risk_score", 75) + 10),
                        confidence=0.88,
                        evidence_ids=all_eids[:5],
                    )
                )
            else:
                recs.append(
                    AIActionRecommendation(
                        action_type="ACCOUNT_LOCKOUT",
                        target_entity=user,
                        target_type="USER",
                        playbook_id="PLAYBOOK-001",
                        reason=f"Temporarily lock account '{user}' under active brute-force targeting.",
                        risk_score=incident.get("risk_score", 65),
                        confidence=0.85,
                        evidence_ids=all_eids[:5],
                    )
                )

        # 3. Host Isolation if multiple hosts or critical
        if len(hostnames) > 1 and incident.get("risk_score", 0) >= 80:
            for host in hostnames:
                recs.append(
                    AIActionRecommendation(
                        action_type="HOST_ISOLATION",
                        target_entity=host,
                        target_type="HOST",
                        playbook_id="PLAYBOOK-004",
                        reason=f"Isolate host '{host}' to contain potential lateral movement.",
                        risk_score=85,
                        confidence=0.75,
                        evidence_ids=all_eids[:5],
                    )
                )

        # 4. L2 Escalation if risk is high
        if incident.get("risk_score", 0) >= 75 or len(hostnames) > 1 or "T1078.003" in mitre_techs:
            recs.append(
                AIActionRecommendation(
                    action_type="L2_ESCALATION",
                    target_entity=str(incident.get("id", "incident")),
                    target_type="INCIDENT",
                    playbook_id="PLAYBOOK-005",
                    reason="Escalate incident to Tier-2 SOC due to high risk score or privileged account compromise.",
                    risk_score=incident.get("risk_score", 85),
                    confidence=0.90,
                    evidence_ids=all_eids[:5],
                )
            )

        return recs


class ExternalAIProvider(AIProvider):
    """
    Adapter for external LLM APIs (Google Gemini, OpenAI-compatible).
    Enforces strict security prompting and untrusted-data boundary isolation.
    Falls back gracefully to DeterministicAIProvider if unconfigured or unreachable.
    """

    def __init__(self, fallback: AIProvider | None = None):
        self.fallback = fallback or DeterministicAIProvider()
        from app.core.config import settings

        provider_type = (settings.AI_PROVIDER or os.getenv("AI_PROVIDER", "gemini")).lower()
        if provider_type == "gemini":
            from app.ai.gemini_provider import GeminiAIProvider

            self._delegate: AIProvider = GeminiAIProvider(fallback=self.fallback)
        else:
            self._delegate = self.fallback

    def __repr__(self) -> str:
        return f"<ExternalAIProvider delegate={self._delegate!r}>"

    def __str__(self) -> str:
        return self.__repr__()

    async def analyze(self, context: dict[str, Any]) -> AIAnalysisResult:
        return await self._delegate.analyze(context)

    async def summarize(self, context: dict[str, Any]) -> str:
        return await self._delegate.summarize(context)

    async def generate_hypotheses(self, context: dict[str, Any]) -> list[AIHypothesis]:
        return await self._delegate.generate_hypotheses(context)

    async def recommend_actions(self, context: dict[str, Any]) -> list[AIActionRecommendation]:
        return await self._delegate.recommend_actions(context)
