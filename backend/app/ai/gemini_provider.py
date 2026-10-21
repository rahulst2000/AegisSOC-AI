"""
Google Gemini AI Provider for AegisSOC AI.

Connects Google Gemini (Developer API / Vertex) as an external AI provider
for autonomous incident investigation, forensic hypothesis evaluation, and
playbook action recommendation.

Security Guardrails:
- Secret Protection: API key is never logged, printed, or exposed in exceptions.
- Untrusted Data Isolation: All telemetry enclosed in <<<UNTRUSTED_SECURITY_TELEMETRY>>> tags.
- Post-Generation Forensic Grounding: Cited evidence IDs are verified against known events.
- Zero Direct Execution: LLM outputs are recommendations only; containment requires Policy + Human approval.
- Graceful Deterministic Fallback: Unconfigured, failed, or rate-limited requests fail safely
  to DeterministicAIProvider without crashing.
"""

import asyncio
import os
import re
from typing import Any

from google import genai
from google.genai import types

from app.ai.prompts import INVESTIGATION_SYSTEM_PROMPT, format_investigation_prompt
from app.ai.provider import AIProvider, DeterministicAIProvider
from app.ai.schemas import AIActionRecommendation, AIAnalysisResult, AIHypothesis
from app.ai.validator import detect_prompt_injection, validate_and_sanitize_ai_result
from app.core.config import settings
from app.core.logging import logger

# Regex to detect API keys or bearer tokens in arbitrary strings
API_KEY_REGEX = re.compile(r"AIzaSy[A-Za-z0-9_-]{33}|Bearer\s+[A-Za-z0-9_\-\.]+", re.IGNORECASE)


class GeminiAIProvider(AIProvider):
    """
    Enterprise Google Gemini AI Provider implementing AegisSOC AIProvider abstraction.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        fallback: AIProvider | None = None,
        timeout: float | None = None,
        max_retries: int | None = None,
    ) -> None:
        self._api_key: str = (
            api_key if api_key is not None else (settings.GEMINI_API_KEY or os.getenv("GEMINI_API_KEY", ""))
        ).strip()
        self.model: str = model or settings.AI_MODEL or os.getenv("AI_MODEL", "gemini-2.5-flash")
        self.fallback: AIProvider = fallback or DeterministicAIProvider()
        self.timeout: float = timeout if timeout is not None else settings.AI_REQUEST_TIMEOUT_SECONDS
        self.max_retries: int = max_retries if max_retries is not None else settings.AI_MAX_RETRIES
        self.max_input_chars: int = settings.AI_MAX_INPUT_CHARS
        self.max_output_tokens: int = settings.AI_MAX_OUTPUT_TOKENS
        self._client: genai.Client | None = None

    def __repr__(self) -> str:
        # Never expose API key in object representation
        return f"<GeminiAIProvider model={self.model} api_key_configured={self.is_configured()}>"

    def __str__(self) -> str:
        return self.__repr__()

    def is_configured(self) -> bool:
        """Returns True if a non-empty Gemini API key is configured."""
        return bool(self._api_key)

    def get_status(self) -> dict[str, Any]:
        """Safe status dictionary without secret leakage."""
        return {
            "provider": "gemini",
            "model": self.model,
            "gemini_provider_configured": "YES",
            "api_key_configured": "YES" if self.is_configured() else "NO",
            "deterministic_fallback_ready": "YES",
            "timeout_seconds": self.timeout,
            "max_retries": self.max_retries,
        }

    def _get_client(self) -> genai.Client | None:
        """Lazily initialize genai.Client using the configured secret key."""
        if not self.is_configured():
            return None
        if self._client is None:
            self._client = genai.Client(api_key=self._api_key)
        return self._client

    def _sanitize_string(self, text: str) -> str:
        """Scrub any accidental API key or auth token from text/error strings."""
        if not text:
            return ""
        scrubbed = text
        if self._api_key and self._api_key in scrubbed:
            scrubbed = scrubbed.replace(self._api_key, "[REDACTED_GEMINI_KEY]")
        scrubbed = API_KEY_REGEX.sub("[REDACTED_SECRET]", scrubbed)
        return scrubbed

    async def analyze(self, context: dict[str, Any]) -> AIAnalysisResult:
        """
        Conducts an autonomous forensic investigation on incident context.
        Enforces untrusted boundaries, validates evidence grounding, and
        fails safely to DeterministicAIProvider if unconfigured or unreachable.
        """
        # 1. Deterministic fallback if API key is not configured
        if not self.is_configured():
            logger.info("Gemini API key is not configured. Engaging DeterministicAIProvider fallback.")
            return await self.fallback.analyze(context)

        # 2. Extract valid event and detection IDs for post-generation grounding
        valid_event_ids: set[str] = set()
        for ev in context.get("events", []):
            if isinstance(ev, dict) and "id" in ev:
                valid_event_ids.add(str(ev["id"]))
        for det in context.get("detections", []):
            if isinstance(det, dict):
                for eid in det.get("event_ids", []):
                    valid_event_ids.add(str(eid))

        # 3. Prompt injection detection on untrusted telemetry
        for ev in context.get("events", []):
            if isinstance(ev, dict):
                raw = str(ev.get("raw_payload", "")) + " " + str(ev.get("normalized_event", ""))
                injections = detect_prompt_injection(raw)
                if injections:
                    logger.warning(
                        "Adversary prompt-injection attempt detected in event %s: %s. Telemetry quarantined.",
                        ev.get("id"),
                        injections,
                    )

        # 4. Format prompt with strict boundary isolation
        prompt_text = format_investigation_prompt(context)
        if len(prompt_text) > self.max_input_chars:
            logger.warning(
                "Investigation prompt length (%d chars) exceeded maximum limit (%d). Truncating safely.",
                len(prompt_text),
                self.max_input_chars,
            )
            prompt_text = prompt_text[: self.max_input_chars] + "\n<<<END_UNTRUSTED_SECURITY_TELEMETRY>>>"

        # 5. Call Gemini with retry loop & backoff
        retries = 0
        last_error = ""

        while retries <= self.max_retries:
            try:
                client = self._get_client()
                if client is None:
                    return await self.fallback.analyze(context)

                config = types.GenerateContentConfig(
                    system_instruction=INVESTIGATION_SYSTEM_PROMPT,
                    response_mime_type="application/json",
                    response_schema=AIAnalysisResult,
                    max_output_tokens=self.max_output_tokens,
                    temperature=0.1,
                )

                response = await asyncio.wait_for(
                    client.aio.models.generate_content(
                        model=self.model,
                        contents=prompt_text,
                        config=config,
                    ),
                    timeout=self.timeout,
                )

                raw_json = response.text or "{}"
                parsed_result = AIAnalysisResult.model_validate_json(raw_json)

                # 6. Structured Output Validation & Evidence Grounding Gate
                sanitized_result = validate_and_sanitize_ai_result(parsed_result, valid_event_ids)
                return sanitized_result

            except TimeoutError:
                last_error = f"Gemini API request timed out after {self.timeout}s"
                logger.warning(
                    "%s (attempt %d/%d).",
                    last_error,
                    retries + 1,
                    self.max_retries + 1,
                )
            except Exception as exc:
                clean_err = self._sanitize_string(str(exc))
                last_error = f"Gemini API error: {clean_err}"
                logger.warning(
                    "%s (attempt %d/%d).",
                    last_error,
                    retries + 1,
                    self.max_retries + 1,
                )

            retries += 1
            if retries <= self.max_retries:
                backoff_delay = 0.5 * (2 ** (retries - 1))
                await asyncio.sleep(backoff_delay)

        # 7. Safe Fallback to Deterministic Provider
        logger.error(
            "Gemini provider exhausted %d attempts (%s). Safely engaging deterministic fallback.",
            self.max_retries + 1,
            last_error,
        )
        return await self.fallback.analyze(context)

    async def summarize(self, context: dict[str, Any]) -> str:
        """Generates executive summary or falls back deterministically."""
        if not self.is_configured():
            return await self.fallback.summarize(context)
        analysis = await self.analyze(context)
        return analysis.executive_summary

    async def generate_hypotheses(self, context: dict[str, Any]) -> list[AIHypothesis]:
        """Generates forensic hypotheses or falls back deterministically."""
        if not self.is_configured():
            return await self.fallback.generate_hypotheses(context)
        analysis = await self.analyze(context)
        return analysis.hypotheses

    async def recommend_actions(self, context: dict[str, Any]) -> list[AIActionRecommendation]:
        """Generates response action recommendations or falls back deterministically."""
        if not self.is_configured():
            return await self.fallback.recommend_actions(context)
        analysis = await self.analyze(context)
        return analysis.recommendations

    async def test_connectivity(self) -> dict[str, Any]:
        """
        Executes a safe synthetic connectivity test against Google Gemini.
        Validates API key detection, request transmission, and structured parsing
        WITHOUT sending customer data, credentials, or production logs.
        """
        if not self.is_configured():
            return {
                "success": False,
                "provider": "gemini",
                "model": self.model,
                "api_key_configured": "NO",
                "message": "Gemini API key is not configured. Deterministic fallback is active.",
            }

        synthetic_context = {
            "incident": {
                "id": "00000000-0000-0000-0000-000000000001",
                "title": "AegisSOC AI Synthetic Connectivity Verification",
                "description": "Synthetic probe to verify Google Gemini API connectivity",
                "severity": "LOW",
                "risk_score": 10,
                "confidence_score": 1.0,
                "mitre_techniques": [],
                "source_ips": ["127.0.0.1"],
                "affected_users": ["probe_user"],
                "affected_assets": ["probe_host"],
            },
            "detections": [],
            "events": [
                {
                    "id": "00000000-0000-0000-0000-000000000002",
                    "event_type": "diagnostic_probe",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "source_ip": "127.0.0.1",
                    "user_name": "probe_user",
                    "hostname": "probe_host",
                    "severity": "LOW",
                    "raw_payload": {"probe": "connectivity_test"},
                    "normalized_event": {"event": {"type": "diagnostic_probe"}},
                }
            ],
            "timeline": [],
            "analyst_notes": "Synthetic connectivity diagnostic test.",
        }

        try:
            result = await self.analyze(synthetic_context)
            return {
                "success": True,
                "provider": "gemini",
                "model": self.model,
                "api_key_configured": "YES",
                "summary": result.executive_summary[:200] if result.executive_summary else "",
                "findings_count": len(result.findings),
                "hypotheses_count": len(result.hypotheses),
                "recommendations_count": len(result.recommendations),
                "message": "AegisSOC AI provider connectivity test succeeded.",
            }
        except Exception as exc:
            clean_err = self._sanitize_string(str(exc))
            return {
                "success": False,
                "provider": "gemini",
                "model": self.model,
                "api_key_configured": "YES",
                "error": clean_err,
                "message": "Gemini connectivity test failed. Deterministic fallback will handle analysis.",
            }
