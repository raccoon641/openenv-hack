"""
inference.py  –  LLM-driven agent for the OpenEnv vulnerability environment.

Usage
-----
    export API_BASE_URL=https://api-inference.huggingface.co/v1
    export MODEL_NAME=meta-llama/Llama-3.1-8B-Instruct
    export HF_TOKEN=hf_...
    python inference.py

    # To test locally with Claude (OpenAI-compatible endpoint):
    export API_BASE_URL=https://api.anthropic.com/v1
    export MODEL_NAME=claude-opus-4-6
    export HF_TOKEN=sk-ant-...

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
import textwrap
from typing import Dict, Tuple

from openai import OpenAI

# ── Local imports ─────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from env import VulnEnv

# ── Configuration ─────────────────────────────────────────────────────────────
API_BASE_URL: str = os.environ.get("API_BASE_URL", "")
MODEL_NAME:   str = os.environ.get("MODEL_NAME",   "")
HF_TOKEN:     str = os.environ.get("HF_TOKEN",     "")

MAX_STEPS:  int   = 5
MAX_TOKENS: int   = 512

# Default fallback when the LLM produces invalid output
_DEFAULT_ACTION = {"type": "input", "target": "query", "payload": "test"}

# ── Prompt builder ────────────────────────────────────────────────────────────

def build_prompt(state: Dict) -> str:
    """
    Construct a minimal, focused prompt that forces the LLM to output
    a single valid JSON action object and nothing else.
    """
    compact_state = {
        "task":          state.get("task"),
        "code_context":  state.get("code_context", "")[:600],
        "recent_output": str(state.get("recent_output", ""))[:300],
        "signals": {
            "alerts": state["signals"].get("alerts", ""),
            "hints":  state["signals"].get("hints",  ""),
        },
        "step_count": state.get("step_count", 0),
    }

    state_json = json.dumps(compact_state, indent=2)

    # Per-task target/payload hints so the model guesses less
    task_id = state.get("task", "")
    if task_id == "sql_injection":
        target_hint  = '"query"'
        payload_hint = "SQL injection string, e.g. \\' OR \\'1\\'=\\'1"
    elif task_id == "auth_bypass":
        target_hint  = '"login"'
        payload_hint = "username string, e.g. \\') or True or (\\'"
    else:  # xss_injection
        target_hint  = '"render"'
        payload_hint = "username::message, e.g. <script>alert(1)</script>::msg"

    return textwrap.dedent(f"""
        You are a security testing agent. Your goal is to exploit a vulnerability.

        Task: {task_id}

        Current State:
        {state_json}

        Available Actions:
        1. input  → {{"type": "input",  "target": {target_hint}, "payload": "<{payload_hint}>"}}
        2. edit   → {{"type": "edit",   "target": "<function>",  "payload": "<mutation>"}}

        Rules:
        - Return ONLY a single valid JSON object.
        - Do NOT include any explanation, markdown, or extra text.
        - Choose the action most likely to trigger the vulnerability.

        Output:
    """).strip()


# ── Action parser + validator ─────────────────────────────────────────────────

def parse_action(raw: str) -> Tuple[Dict, bool]:
    """
    Extract a valid action from the LLM's raw output.
    Returns (action_dict, is_valid). Falls back to _DEFAULT_ACTION on failure.
    """
    raw = raw.strip()

    # Strip markdown code fences if the model wrapped the output
    if raw.startswith("```"):
        raw = "\n".join(
            line for line in raw.splitlines()
            if not line.startswith("```")
        ).strip()

    try:
        action = json.loads(raw)
    except json.JSONDecodeError:
        # Try to extract the first {...} block from surrounding prose
        start = raw.find("{")
        end   = raw.rfind("}") + 1
        if start != -1 and end > start:
            try:
                action = json.loads(raw[start:end])
            except json.JSONDecodeError:
                return _DEFAULT_ACTION.copy(), False
        else:
            return _DEFAULT_ACTION.copy(), False

    if not isinstance(action, dict):
        return _DEFAULT_ACTION.copy(), False
    if action.get("type") not in ("input", "edit"):
        return _DEFAULT_ACTION.copy(), False
    if "payload" not in action:
        return _DEFAULT_ACTION.copy(), False

    return action, True


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
    Call the LLM with the current state prompt and return a validated action.
    Retries once on invalid output, then falls back to the default action.
    """
    prompt = build_prompt(state)

    for attempt in range(2):
        try:
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=MAX_TOKENS,
            )
            raw_output = response.choices[0].message.content or ""
        except Exception as exc:
            print(f"  [WARN] LLM call failed (attempt {attempt+1}): {exc}", file=sys.stderr)
            raw_output = ""

        action, valid = parse_action(raw_output)
        if valid:
            return action

        # Retry with a stricter reminder
        prompt += "\n\nIMPORTANT: output ONLY a JSON object — no explanation, no markdown."

    return _DEFAULT_ACTION.copy()


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
