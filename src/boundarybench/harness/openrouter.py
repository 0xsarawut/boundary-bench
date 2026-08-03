"""OpenRouter provider helpers shared by harness adapters.

Lives in the harness package so adapters never have to reach back into the
runner layer they are meant to abstract.
"""

from __future__ import annotations

import re

OPENROUTER_ORIGIN = "https://openrouter.ai"

ACCOUNTING_PROXY_HOST = "127.0.0.1"
ACCOUNTING_PROXY_PORT = 18082
ACCOUNTING_PROXY_ORIGIN = f"http://{ACCOUNTING_PROXY_HOST}:{ACCOUNTING_PROXY_PORT}"

OPENROUTER_BASE_URL = f"{ACCOUNTING_PROXY_ORIGIN}/api"

_OPENROUTER_MODEL_RE = re.compile(r"^[A-Za-z0-9._/:-]+$")


def validate_openrouter_model_id(model: str) -> str:
    """Validate the model id before embedding it in a shell command."""

    model = (model or "").strip()
    if not model or not _OPENROUTER_MODEL_RE.fullmatch(model):
        raise ValueError(
            f"OpenRouter model id must match ^[A-Za-z0-9._/:-]+$; got {model!r}"
        )
    return model
