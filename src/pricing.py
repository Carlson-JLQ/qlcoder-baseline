"""Per-model pricing used to compute API costs ourselves.

The agent CLIs price models from their own built-in tables. A proxied model
they do not recognize (e.g. deepseek-v4.1-flash-itkk) is priced at the vendor's
list rate for whatever slot it lands in — Claude Code uses Opus rates and
reports ``costBasis: "unknown"`` — so the ``total_cost_usd`` field in CLI output
is not usable for these models. Models with no row here fall back to the cost
the CLI reports, which is correct for genuine Claude models.
"""

import re
from typing import Dict, Optional

# USD per one million tokens.
MODEL_PRICING: Dict[str, Dict[str, float]] = {
    "deepseek-v4.1-flash-itkk": {
        "input_cache_hit": 0.04,
        "input_cache_miss": 2.0,
        # The published table has no cache-write rate; cache writes are billed
        # as cache-miss input until a separate rate is provided.
        "cache_write": 2.0,
        "output": 8.0,
    },
}

# Context-size markers such as "[1M]" are part of the model selector, not the
# model name, and the CLI lowercases them in its usage report.
_CONTEXT_SUFFIX = re.compile(r"\[[^\]]*\]\s*$")


def normalize_model_id(model: str) -> str:
    """Map a CLI spelling such as ``deepseek-v4.1-flash-itkk[1m]`` to a pricing key."""
    if not model:
        return ""
    return _CONTEXT_SUFFIX.sub("", model.strip()).lower()


def get_pricing(model: str) -> Optional[Dict[str, float]]:
    """Return the pricing row for a model, or None when it is not priced here."""
    return MODEL_PRICING.get(normalize_model_id(model))


def compute_cost(
    model: str,
    input_tokens: int,
    cache_read_tokens: int,
    cache_creation_tokens: int,
    output_tokens: int,
) -> Optional[float]:
    """Return the USD cost for one usage record, or None if the model is unpriced.

    ``input_tokens`` from the CLI excludes cache reads: a request served from
    cache reports the cached portion under ``cache_read_input_tokens`` and only
    the remainder as input, so the four counts do not overlap.
    """
    pricing = get_pricing(model)
    if pricing is None:
        return None
    return (
        input_tokens * pricing["input_cache_miss"]
        + cache_read_tokens * pricing["input_cache_hit"]
        + cache_creation_tokens * pricing["cache_write"]
        + output_tokens * pricing["output"]
    ) / 1_000_000
