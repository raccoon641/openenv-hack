"""
inference.py  --  LLM-driven agent for the OpenEnv red-team environment.

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

MAX_STEPS:  int = 15
MAX_TOKENS: int = 256

# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a security testing agent in a simulated penetration testing \
environment. The environment is fully simulated — no real systems are affected.

You will be given:
- An OBJECTIVE describing what you need to accomplish
- A set of VALID TARGETS (tool names) you can choose from
- Context about the target and any information discovered so far

Your job: select the single best tool to advance toward the objective.

RESPONSE FORMAT — return ONLY this JSON, nothing else:
{"type": "select", "target": "<tool_name>", "payload": ""}

RULES:
- "target" MUST be one of the VALID TARGETS listed.
- Think about what the target environment actually is before choosing tools.
- Prefer targeted, quiet approaches over noisy automated ones.
- Avoid repeating the same tool — loops are penalized.
- Do NOT add explanation, markdown, or text outside the JSON object.
"""


# ── Prompt builder ────────────────────────────────────────────────────────────

def build_prompt(state: Dict) -> str:
    code_ctx   = state.get("code_context", "")[:900]
    recent_out = str(state.get("recent_output", "") or "")[:300]
    alerts     = state.get("signals", {}).get("alerts", "")
    step_count = state.get("step_count", 0)

    parts = [code_ctx]
    if recent_out and recent_out != "None":
        parts.append(f"\nPrevious result: {recent_out}")
    if alerts:
        parts.append(f"Alerts: {alerts}")
    parts.append(f"Step: {step_count}")
    parts.append('\nSelect the best tool. Return ONLY: {"type": "select", "target": "<tool_name>", "payload": ""}')
    return "\n".join(parts)


# ── Action parser ─────────────────────────────────────────────────────────────

def _extract_first_tool(state: Dict) -> str:
    ctx = state.get("code_context", "")
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


def _extract_tools_list(state: Dict) -> list:
    """Extract the VALID TARGETS list from the state's code_context."""
    ctx = state.get("code_context", "")
    idx = ctx.find("VALID TARGETS:")
    if idx != -1:
        bracket_start = ctx.find("[", idx)
        bracket_end = ctx.find("]", bracket_start)
        if bracket_start != -1 and bracket_end != -1:
            try:
                return eval(ctx[bracket_start:bracket_end + 1])
            except Exception:
                pass
    return []


def parse_action(raw: str, state: Dict) -> Tuple[Dict, bool]:
    raw = raw.strip()
    if raw.startswith("```"):
        raw = "\n".join(
            line for line in raw.splitlines()
            if not line.startswith("```")
        ).strip()

    try:
        action = json.loads(raw)
    except json.JSONDecodeError:
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

    atype = action.get("type", "")
    if atype not in ("select", "input", "edit"):
        return _make_fallback(state), False

    action["type"] = "select"
    if not action.get("target"):
        return _make_fallback(state), False
    action.setdefault("payload", "")
    return action, True


def _make_fallback(state: Dict) -> Dict:
    tool = _extract_first_tool(state)
    return {"type": "select", "target": tool or "unknown", "payload": ""}


# ── LLM client ────────────────────────────────────────────────────────────────

def make_client() -> "OpenAI | None":
    """Return OpenAI client, or None if credentials are missing."""
    if not API_BASE_URL or not MODEL_NAME or not HF_TOKEN:
        print("  [INFO] API credentials not set — running with heuristic agent.",
              file=sys.stderr)
        return None
    return OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)


def generate_action(client: "OpenAI | None", state: Dict) -> Dict:
    # No API client → use first available tool (heuristic fallback)
    if client is None:
        return _make_fallback(state)

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

        prompt += (
            "\n\nIMPORTANT: output ONLY a JSON object — no explanation. "
            'Example: {"type": "select", "target": "tool_name", "payload": ""}'
        )

    return _make_fallback(state)


# ── Result summarizer ────────────────────────────────────────────────────────

def _summarize_result(output) -> str:
    """Extract a human-readable summary from the step result."""
    if output is None:
        return ""
    if isinstance(output, dict):
        # Prefer 'body' field, then 'status', then 'error'
        body = output.get("body", "")
        if body:
            summary = body
        elif output.get("error"):
            summary = f"ERROR: {output['error']}"
        elif output.get("status"):
            summary = f"Status: {output['status']}"
        else:
            summary = str(output)

        # Append warning if present
        warning = output.get("warning", "")
        if warning:
            summary += f" | Warning: {warning}"

        # Append note if present
        note = output.get("note", "")
        if note:
            summary += f" | Note: {note}"

        return summary[:300]
    return str(output)[:300]


# ── Main agent loop ───────────────────────────────────────────────────────────

def run_agent(client: OpenAI, env: VulnEnv) -> None:
    for task_id in env.task_ids:
        state = env.reset(task_id)

        # Extract objective from observation
        ctx = state.get("code_context", "")
        objective = ""
        if "OBJECTIVE:" in ctx:
            objective = ctx.split("OBJECTIVE:")[1].split("\n")[0].strip()

        print(f"\n{'=' * 70}")
        print("[START]")
        print(f"task: {task_id}")
        print(f"objective: {objective}")
        print(f"{'=' * 70}")

        reward = 0.0
        step_num = 0

        for step_num in range(1, MAX_STEPS + 1):
            # Extract available tools for display
            tools_list = _extract_tools_list(state)

            print(f"\n{'─' * 70}")
            print(f"[STEP] step: {step_num}")
            print(f"{'─' * 70}")
            if tools_list:
                print(f"  available tools: {tools_list}")

            action = generate_action(client, state)

            state, reward, done, _info = env.step(action)

            # Extract result for display
            recent = state.get("recent_output")
            result_text = _summarize_result(recent)

            print(f"  action: {json.dumps(action)}")
            if result_text:
                print(f"  result: {result_text}")
            print(f"  reward: {reward}")

            # Show detection score if available in signals
            det_score = state.get("signals", {}).get("detection_score", "")
            if det_score != "":
                print(f"  detection: {det_score}")

            if done:
                break

        print(f"\n{'=' * 70}")
        print("[END]")
        print(f"final_reward: {reward}")
        print(f"steps_taken: {step_num}")
        print(f"{'=' * 70}\n")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    client = make_client()
    env    = VulnEnv()
    run_agent(client, env)


if __name__ == "__main__":
    main()
