"""LLM provider abstraction for the investigation assistant.

The deterministic security engines never depend on an LLM. The assistant uses one
only to phrase an answer over evidence we supply; when no API key is configured
(or the SDK/network is unavailable) the service falls back to a deterministic
responder. Providers must fail soft: any problem returns None so the caller falls
back rather than erroring.
"""

from typing import Protocol

from app.core.config import Settings


class LLMProvider(Protocol):
    name: str

    def available(self) -> bool: ...

    def generate(self, system: str, user: str) -> str | None: ...


class AnthropicProvider:
    """Calls the Anthropic Messages API if the SDK and a key are present."""

    name = "anthropic"

    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model

    def available(self) -> bool:
        if not self.api_key:
            return False
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False
        return True

    def generate(self, system: str, user: str) -> str | None:
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=self.api_key)
            message = client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            parts = [
                block.text for block in message.content if getattr(block, "type", "") == "text"
            ]
            text = "\n".join(parts).strip()
            return text or None
        except Exception:  # noqa: BLE001 - fail soft to the deterministic responder
            return None


def get_provider(settings: Settings) -> LLMProvider | None:
    if settings.llm_api_key:
        return AnthropicProvider(settings.llm_api_key, settings.llm_model)
    return None
