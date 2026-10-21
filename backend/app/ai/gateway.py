import os
from typing import Any

from app.ai.gemini_provider import GeminiAIProvider
from app.ai.provider import AIProvider, DeterministicAIProvider, ExternalAIProvider
from app.core.config import settings

_ai_provider_instance: AIProvider | None = None


def get_ai_provider() -> AIProvider:
    """
    Returns the configured AI Provider singleton.
    Defaults to ExternalAIProvider (Gemini) with DeterministicAIProvider fallback.
    """
    global _ai_provider_instance
    if _ai_provider_instance is None:
        has_key = bool(settings.GEMINI_API_KEY or os.getenv("GEMINI_API_KEY"))
        provider_name = (settings.AI_PROVIDER or os.getenv("AI_PROVIDER", "gemini")).lower()

        if provider_name == "deterministic":
            _ai_provider_instance = DeterministicAIProvider()
        elif os.getenv("ENVIRONMENT") == "testing" and not has_key:
            _ai_provider_instance = DeterministicAIProvider()
        elif provider_name == "gemini":
            _ai_provider_instance = GeminiAIProvider()
        else:
            _ai_provider_instance = ExternalAIProvider()
    return _ai_provider_instance


def set_ai_provider(provider: AIProvider | None) -> None:
    """Sets or resets the AI Provider instance (primarily for testing)."""
    global _ai_provider_instance
    _ai_provider_instance = provider


def get_ai_provider_status() -> dict[str, Any]:
    """
    Reports AI Provider configuration status without exposing sensitive credentials.
    """
    has_key = bool(settings.GEMINI_API_KEY or os.getenv("GEMINI_API_KEY"))
    active_provider = get_ai_provider()

    return {
        "provider": settings.AI_PROVIDER,
        "model": settings.AI_MODEL,
        "gemini_provider_configured": "YES" if settings.AI_PROVIDER == "gemini" else "NO",
        "api_key_configured": "YES" if has_key else "NO",
        "deterministic_fallback_ready": "YES",
        "active_provider_class": active_provider.__class__.__name__,
    }
