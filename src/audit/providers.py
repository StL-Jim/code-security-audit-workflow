"""
Provider configuration, per-node model routing, and cost tracking.

Mirrors threat-modeling-workflow's provider handling, extended with:
- mixed routing: judgment-heavy nodes can use a different (stronger) provider
  than the bulk scanning nodes
- a CostMeter that records response.usage per call and writes costs.md
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(_PROJECT_ROOT / ".env")

from anthropic import Anthropic

PROVIDER_CONFIGS = {
    "anthropic": {
        "api_key_env": "ANTHROPIC_API_KEY",
        "base_url": None,
        "default_model": "claude-sonnet-4-6",
    },
    "minimax": {
        "api_key_env": "MINIMAX_API_KEY",
        "base_url": "https://api.minimax.io/anthropic",
        "default_model": "MiniMax-M3",
    },
}

# USD per million tokens: (input, output). Estimates only -- update when
# provider pricing changes. Unknown models are logged with token counts only.
MODEL_PRICING = {
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-haiku-4-5": (1.00, 5.00),
    "MiniMax-M3": (0.30, 1.20),   # placeholder: MiniMax-M2 list price; verify M3
    "MiniMax-M2": (0.30, 1.20),
}

# Node-id keywords that route to the judgment provider (typically Anthropic).
# Everything else uses the bulk provider (typically MiniMax).
JUDGMENT_NODE_KEYWORDS = {
    "prioritiz",          # Phase 2 risk prioritization
    "cross_reference",    # threat cross-reference (confirms/partial/unanticipated)
    "consolidat",         # Phase 5 consolidation
    "comparison",         # threat-audit comparison content
    "executive",          # executive briefing
}


def model_pricing(model: str) -> Optional[tuple[float, float]]:
    if model in MODEL_PRICING:
        return MODEL_PRICING[model]
    for known, price in MODEL_PRICING.items():
        if model.lower().startswith(known.lower()):
            return price
    return None


def make_client(provider: str) -> tuple[Anthropic, str]:
    cfg = PROVIDER_CONFIGS.get(provider.lower())
    if cfg is None:
        raise ValueError(
            f"Unknown provider '{provider}'. Choose from: {', '.join(PROVIDER_CONFIGS)}"
        )
    api_key = os.environ.get(cfg["api_key_env"])
    if not api_key:
        raise EnvironmentError(
            f"Provider '{provider}' requires {cfg['api_key_env']} in your .env file."
        )
    kwargs = {"api_key": api_key}
    if cfg["base_url"]:
        kwargs["base_url"] = cfg["base_url"]
    return Anthropic(**kwargs), cfg["default_model"]


def is_judgment_node(node_id: str) -> bool:
    nid = node_id.lower()
    return any(kw in nid for kw in JUDGMENT_NODE_KEYWORDS)


class ModelRouter:
    """Resolves (client, model, provider_name) for a given node id."""

    def __init__(self, bulk_provider: str, judgment_provider: Optional[str] = None,
                 bulk_model: Optional[str] = None, judgment_model: Optional[str] = None):
        client, default_model = make_client(bulk_provider)
        self.bulk = (client, bulk_model or default_model, bulk_provider)
        if judgment_provider and judgment_provider != bulk_provider:
            j_client, j_default = make_client(judgment_provider)
            self.judgment = (j_client, judgment_model or j_default, judgment_provider)
        else:
            self.judgment = self.bulk

    def for_node(self, node_id: str) -> tuple[Anthropic, str, str]:
        return self.judgment if is_judgment_node(node_id) else self.bulk


class CostMeter:
    """Records response.usage per LLM call; prints a tally and appends costs.md."""

    def __init__(self, costs_file: Path):
        self.costs_file = costs_file
        self.usage_log: list[dict] = []
        self._header_written = False

    def record(self, label: str, model: str, provider: str, response) -> None:
        usage = getattr(response, "usage", None)
        in_tok = int(getattr(usage, "input_tokens", 0) or 0)
        out_tok = int(getattr(usage, "output_tokens", 0) or 0)
        pricing = model_pricing(model)
        cost = None
        if pricing:
            cost = (in_tok * pricing[0] + out_tok * pricing[1]) / 1_000_000
        self.usage_log.append(
            {"node": label, "model": model, "input": in_tok,
             "output": out_tok, "cost": cost}
        )
        total = sum(e["cost"] for e in self.usage_log if e["cost"] is not None)
        cost_str = f"${cost:.4f}" if cost is not None else "n/a (model not in MODEL_PRICING)"
        print(f"  Tokens: {in_tok:,} in / {out_tok:,} out -- {cost_str}"
              f" (session total ${total:.4f})")
        self._append_row(label, model, provider, in_tok, out_tok, cost)

    def _append_row(self, label: str, model: str, provider: str,
                    in_tok: int, out_tok: int, cost: Optional[float]) -> None:
        self.costs_file.parent.mkdir(parents=True, exist_ok=True)
        new_file = not self.costs_file.exists()
        with open(self.costs_file, "a", encoding="utf-8") as f:
            if new_file:
                f.write(
                    "# LLM Usage and Cost Log\n\n"
                    "Costs are estimates from MODEL_PRICING in providers.py "
                    "(USD per million tokens).\n"
                )
            if not self._header_written:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"\n## Session {ts}\n\n")
                f.write("| Node | Provider/Model | Input tokens | Output tokens | Cost (USD) |\n")
                f.write("|------|----------------|--------------|---------------|------------|\n")
                self._header_written = True
            cost_str = f"{cost:.4f}" if cost is not None else "n/a"
            safe_label = label.replace("|", "/")
            f.write(f"| {safe_label} | {provider}/{model} | {in_tok} | {out_tok} | {cost_str} |\n")

    def finalize(self) -> None:
        if not self.usage_log:
            return
        tin = sum(e["input"] for e in self.usage_log)
        tout = sum(e["output"] for e in self.usage_log)
        tcost = sum(e["cost"] for e in self.usage_log if e["cost"] is not None)
        with open(self.costs_file, "a", encoding="utf-8") as f:
            f.write(f"| SESSION TOTAL | -- | {tin} | {tout} | {tcost:.4f} |\n")
        print(f"  LLM usage this session: {tin:,} in / {tout:,} out -- ~${tcost:.4f}")
        print(f"  Cost log: {self.costs_file}")
