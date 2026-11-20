"""
shadow_strike.agent.llm_providers
====================================
Real LLM adapters matching the `LLMFn = Callable[[str], str]` signature
every node in agent/nodes.py already accepts via `llm_fn=`.

Provider/network behavior is covered by mocked tests. Live Anthropic calls
require an ANTHROPIC_API_KEY and network access; examples/run_demo.py runs
offline without this provider.

Usage:
    from shadow_strike.agent.llm_providers import AnthropicLLM
    llm = AnthropicLLM(api_key=os.environ["ANTHROPIC_API_KEY"])
    graph = SimpleShadowStrikeGraph(executor=..., llm_fn=llm)
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


class LLMProviderError(RuntimeError):
    pass


class AnthropicLLM:
    """Zero-extra-dependency client (stdlib urllib, no `anthropic` package
    required) — one POST to /v1/messages per call. Swap in the official
    SDK if you want streaming/retries/tool-use; this is intentionally
    the minimum viable real implementation."""

    API_URL = "https://api.anthropic.com/v1/messages"
    DEFAULT_MODEL = "claude-sonnet-4-6"

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        max_tokens: int = 1024,
        system_prompt: str | None = None,
        timeout_seconds: int = 30,
    ):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise LLMProviderError(
                "no API key: pass api_key=... or set ANTHROPIC_API_KEY"
            )
        self.model = model or self.DEFAULT_MODEL
        self.max_tokens = max_tokens
        self.timeout_seconds = timeout_seconds
        self.system_prompt = system_prompt or (
            "You are the reasoning layer inside Shadow Strike Protocol, a smart "
            "contract security research lab. You propose attack hypotheses and "
            "scenario adjustments. You NEVER declare an attack successful — only "
            "the deterministic Verifier does that, from actual EVM execution "
            "results. Be specific and concise; your output is consumed "
            "programmatically by the next pipeline stage, not displayed raw."
        )

    def __call__(self, prompt: str) -> str:
        """Matches the LLMFn signature every agent node expects."""
        body = json.dumps({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": self.system_prompt,
            "messages": [{"role": "user", "content": prompt}],
        }).encode("utf-8")

        req = urllib.request.Request(
            self.API_URL,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                payload = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise LLMProviderError(f"Anthropic API returned HTTP {e.code}: {e.read().decode(errors='replace')}") from e
        except urllib.error.URLError as e:
            raise LLMProviderError(f"could not reach Anthropic API: {e}") from e
        except (TimeoutError, json.JSONDecodeError, UnicodeDecodeError) as e:
            raise LLMProviderError(f"Anthropic API request or response failed: {e}") from e

        if not isinstance(payload, dict) or not isinstance(payload.get("content"), list):
            raise LLMProviderError(f"unexpected response shape: {payload}")
        text_blocks = []
        for block in payload["content"]:
            if not isinstance(block, dict):
                raise LLMProviderError(f"unexpected content block: {block}")
            if block.get("type") == "text":
                if not isinstance(block.get("text"), str):
                    raise LLMProviderError(f"unexpected text content: {block}")
                text_blocks.append(block["text"])
        if not text_blocks:
            raise LLMProviderError(f"unexpected response shape (no text content): {payload}")
        return "\n".join(text_blocks)


class EchoLLM:
    """Trivial test double — returns the prompt's last line. Useful for
    exercising the llm_fn code paths in nodes.py without any network
    call or API key, which is what the bundled test suite actually uses
    where it needs *a* callable, as opposed to testing real reasoning
    quality (that needs AnthropicLLM + a real key, by definition)."""

    def __call__(self, prompt: str) -> str:
        return prompt.strip().splitlines()[-1] if prompt.strip() else ""


def build_llm_fn(provider: str | None, api_key: str | None = None):
    """Build an llm_fn from a provider name (Part 10).

    None -> None (heuristics only, no LLM). "echo" -> EchoLLM test double.
    "anthropic" -> AnthropicLLM (key from the argument or ANTHROPIC_API_KEY;
    raises LLMProviderError when no key is available). Anything else raises
    ValueError.
    """
    if provider is None:
        return None
    if provider == "echo":
        return EchoLLM()
    if provider == "anthropic":
        return AnthropicLLM(api_key=api_key)
    raise ValueError(f"unknown llm provider: {provider!r} (expected 'anthropic' or 'echo')")
