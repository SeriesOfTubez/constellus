"""Test-only role bindings for the LLM connector (planning#224 item 5).

Application code carries no model ids: `llm.role_bindings` has no default
in `app_settings.DEFAULTS`, so a fresh install reports "AI models not
configured". The suite still needs bindings to exercise the call path, so
`conftest.py` stores these once per session (the shape of an install whose
admin has saved bindings) and removes them at the end. Tests of the
unconfigured state delete the row themselves and restore it.

The ids are the ones the code default named until planning#224, kept so the
existing assertions on served/requested models still read naturally. They
are fixtures, not a recommendation.
"""

TEST_ROLE_BINDINGS = {
    "classify": {"models": ["deepseek/deepseek-v4-flash", "z-ai/glm-5.3-flash", "google/gemini-2.5-flash-lite"], "max_tokens": 1024, "temperature": 0},
    "extract":  {"models": ["z-ai/glm-5.3-flash", "deepseek/deepseek-v4-flash", "openai/gpt-5-mini"], "max_tokens": 4096, "temperature": 0},
    "research": {"models": ["z-ai/glm-5.3", "moonshotai/kimi-k2.6", "deepseek/deepseek-v4-pro"], "max_tokens": 8192, "temperature": 0.2},
    "judge":    {"models": ["deepseek/deepseek-v4-pro", "anthropic/claude-sonnet-5", "google/gemini-3.1-pro-preview"], "max_tokens": 4096, "temperature": 0},
    "narrate":  {"models": ["google/gemini-3.8-flash", "moonshotai/kimi-k2.6", "z-ai/glm-5.3"], "max_tokens": 2048, "temperature": 0.4},
}
