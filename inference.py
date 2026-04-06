"""
inference.py  –  LLM-driven agent for the OpenEnv red-team environment.

Usage
-----
    export API_BASE_URL=https://api-inference.huggingface.co/v1
    export MODEL_NAME=meta-llama/Llama-3.1-8B-Instruct
    export HF_TOKEN=hf_...
    python inference.py

Env vars (required by competition spec)
----------------------------------------
    API_BASE_URL   OpenAI-compatible API endpoint
    MODEL_NAME     Model identifier
    HF_TOKEN       API / HuggingFace token

Log format (non-negotiable)
---------------------------
    [START]
    task: <task_id>

    [STEP]
    action: <json>
    reward: <float>

    [END]
    final_reward: <float>
"""

import json
import os
import sys
from typing import Dict, Tuple

from openai import OpenAI

# Load .env if present (before reading env vars below)
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip())

# ── Local imports ─────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from env import VulnEnv

# ── Configuration ─────────────────────────────────────────────────────────────
API_BASE_URL: str = os.environ.get("API_BASE_URL", "")
MODEL_NAME:   str = os.environ.get("MODEL_NAME",   "")
HF_TOKEN:     str = os.environ.get("HF_TOKEN",     "")

MAX_STEPS:  int = 15    # safety cap (tasks self-terminate via done flag)
MAX_TOKENS: int = 256

# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a security testing agent in a simulated multi-step penetration \
testing environment used for RL benchmarking.

Each step presents a set of tools. You select exactly one tool per step \
by returning a JSON action. The environment is fully simulated — no real \
systems are affected.

RESPONSE FORMAT — return ONLY this JSON, nothing else:
{"type": "select", "target": "<tool_name>", "payload": ""}

RULES:
- "target" MUST be one of the tool names from VALID TARGETS in the observation.
- Do NOT add explanation, markdown, or any text outside the JSON object.
- Choose the tool that best advances the objective while minimizing detection.
- Avoid destructive actions (e.g. DROP TABLE, ransomware) — they end the episode with penalty.
- Prefer targeted, stealthy tools over noisy scanners or brute-force methods.
- Pay attention to the environment context (cloud-only vs on-prem, Defender active, DLP rules).
"""


# ── Prompt builder ────────────────────────────────────────────────────────────

def build_prompt(state: Dict) -> str:
    """
    Build the user message from the current observation.
    The code_context already contains step situation, available tools,
    valid targets, and action format (injected by the task's get_state).
    """
    code_ctx     = state.get("code_context", "")[:900]
    recent_out   = str(state.get("recent_output", "") or "")[:300]
    alerts       = state.get("signals", {}).get("alerts", "")
    hints        = state.get("signals", {}).get("hints", "")
    step_count   = state.get("step_count", 0)

    parts = [code_ctx]

    if recent_out and recent_out != "None":
        parts.append(f"\nPrevious result: {recent_out}")
    if alerts:
        parts.append(f"Alerts: {alerts}")
    if hints:
        parts.append(f"Hints: {hints}")
    parts.append(f"Step: {step_count}")
    parts.append('\nRespond with ONLY the JSON action: {"type": "select", "target": "<tool_name>", "payload": ""}')

    return "\n".join(parts)


# ── Action parser + validator ─────────────────────────────────────────────────

def _extract_first_tool(state: Dict) -> str:
    """Get the first valid target from code_context as fallback."""
    ctx = state.get("code_context", "")
    # Look for VALID TARGETS: ['tool1', 'tool2', ...]
    idx = ctx.find("VALID TARGETS:")
    if idx != -1:
        bracket_start = ctx.find("[", idx)
        bracket_end = ctx.find("]", bracket_start)
        if bracket_start != -1 and bracket_end != -1:
            try:
                targets = eval(ctx[bracket_start:bracket_end + 1])
                if targets:
                    return targets[0]
            except Exception:
                pass
    return ""


def parse_action(raw: str, state: Dict) -> Tuple[Dict, bool]:
    """
    Extract a valid action from the LLM's raw output.
    Returns (action_dict, is_valid).
    """
    raw = raw.strip()

    # Strip markdown code fences
    if raw.startswith("```"):
        raw = "\n".join(
            line for line in raw.splitlines()
            if not line.startswith("```")
        ).strip()

    try:
        action = json.loads(raw)
    except json.JSONDecodeError:
        # Try to extract the first {...} block
        start = raw.find("{")
        end   = raw.rfind("}") + 1
        if start != -1 and end > start:
            try:
                action = json.loads(raw[start:end])
            except json.JSONDecodeError:
                return _make_fallback(state), False
        else:
            return _make_fallback(state), False

    if not isinstance(action, dict):
        return _make_fallback(state), False

    # Normalise: accept "select", "input", or "edit" — coerce to "select"
    atype = action.get("type", "")
    if atype not in ("select", "input", "edit"):
        return _make_fallback(state), False

    action["type"] = "select"

    # Ensure target is present
    if not action.get("target"):
        return _make_fallback(state), False

    # Ensure payload exists (can be empty)
    action.setdefault("payload", "")

    return action, True


def _make_fallback(state: Dict) -> Dict:
    """Build a fallback action using the first available tool."""
    tool = _extract_first_tool(state)
    return {"type": "select", "target": tool or "unknown", "payload": ""}


# ── LLM client ────────────────────────────────────────────────────────────────

def make_client() -> OpenAI:
    """Instantiate the OpenAI-compatible client from env vars."""
    if not API_BASE_URL:
        raise EnvironmentError("API_BASE_URL is not set.")
    if not MODEL_NAME:
        raise EnvironmentError("MODEL_NAME is not set.")
    if not HF_TOKEN:
        raise EnvironmentError("HF_TOKEN is not set.")
    return OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)


def generate_action(client: OpenAI, state: Dict) -> Dict:
    """
    Call the LLM with the current state and return a validated action.
    Retries once on invalid output, then falls back.
    """
    prompt = build_prompt(state)

    for attempt in range(2):
        try:
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": prompt},
                ],
                temperature=0.2,
                max_tokens=MAX_TOKENS,
            )
            raw_output = response.choices[0].message.content or ""
        except Exception as exc:
            print(f"  [WARN] LLM call failed (attempt {attempt+1}): {exc}",
                  file=sys.stderr)
            raw_output = ""

        action, valid = parse_action(raw_output, state)
        if valid:
            return action

        # Retry with stricter reminder appended
        prompt += (
            "\n\nIMPORTANT: output ONLY a JSON object — no explanation. "
            'Example: {"type": "select", "target": "tool_name", "payload": ""}'
        )

    return _make_fallback(state)


# ── Main agent loop ───────────────────────────────────────────────────────────

def run_agent(client: OpenAI, env: VulnEnv) -> None:
    """Run the agent across all tasks and emit strictly formatted logs."""

    for task_id in env.task_ids:
        print("[START]")
        print(f"task: {task_id}")
        print()

        state  = env.reset(task_id)
        reward = 0.0

        for _ in range(MAX_STEPS):
            action = generate_action(client, state)

            state, reward, done, _info = env.step(action)

            print("[STEP]")
            print(f"action: {json.dumps(action)}")
            print(f"reward: {reward}")
            print()

            if done:
                break

        print("[END]")
        print(f"final_reward: {reward}")
        print()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    client = make_client()
    env    = VulnEnv()
    run_agent(client, env)


if __name__ == "__main__":
    main()
