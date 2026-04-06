"""
app.py  –  OpenEnv-compliant FastAPI server for HuggingFace Space deployment.

Implements the openenv-core HTTPEnvServer contract exactly:

    POST /reset   body: {} or {"task": "<id>"}
                  → {"observation": {...}, "reward": null, "done": false}

    POST /step    body: {"action": {"type":..,"target":..,"payload":..}}
                  → {"observation": {...}, "reward": float, "done": bool}

    GET  /state   → {"episode_id": null, "step_count": int}
    GET  /health  → {"status": "healthy"}
    GET  /tasks   → {"tasks": [...]}

HF Space URL: https://revrse-openenv-redteaming.hf.space
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from typing import Any, Dict, Optional

from fastapi import Body, FastAPI, HTTPException

from env import VulnEnv

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="OpenEnv Red-Team Environment",
    description="Multi-step red-team tasks: SQL Injection, Spear-Phishing, Cloud Identity, AI Exploitation",
    version="1.0.0",
)

_env           = VulnEnv()
_current_obs:  Optional[Dict] = None
_step_count:   int             = 0
_current_task: str             = _env.task_ids[0]   # default task


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_observation(state: Dict) -> Dict:
    """Strip reward/done from state dict and return as observation payload."""
    return {
        "task":          state.get("task", ""),
        "code_context":  state.get("code_context", ""),
        "recent_action": state.get("recent_action"),
        "recent_output": str(state.get("recent_output", "") or ""),
        "signals":       state.get("signals", {}),
        "step_count":    state.get("step_count", 0),
    }


# ── Endpoints (openenv-core HTTPEnvServer contract) ───────────────────────────

@app.get("/health")
def health():
    """Liveness probe — returns 200 {"status": "healthy"}."""
    return {"status": "healthy", "tasks": _env.task_ids}


@app.get("/tasks")
def list_tasks():
    """Enumerate available task IDs."""
    return {"tasks": _env.task_ids}


@app.post("/reset")
def reset(request: Dict[str, Any] = Body(default={})):
    """
    Reset the environment.

    Accepts:
        {}                        → resets to default task (sql_injection)
        {"task": "auth_bypass"}  → resets to specified task

    Returns openenv-core format:
        {"observation": {...}, "reward": null, "done": false}
    """
    global _current_obs, _step_count, _current_task

    task = request.get("task", _current_task)
    if task not in _env.task_ids:
        task = _env.task_ids[0]

    _current_task = task

    try:
        state = _env.reset(task)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    _current_obs  = state
    _step_count   = 0

    return {
        "observation": _make_observation(state),
        "reward":      None,
        "done":        False,
    }


@app.post("/step")
def step(request: Dict[str, Any] = Body(...)):
    """
    Apply a structured action.

    Accepts:
        {"action": {"type": "select", "target": "<tool_name>", "payload": ""}}

    Returns openenv-core format:
        {"observation": {...}, "reward": float, "done": bool}
    """
    global _current_obs, _step_count

    if _current_obs is None:
        raise HTTPException(
            status_code=400,
            detail="Not initialised. Call POST /reset first."
        )

    action = request.get("action", {})
    if not action:
        raise HTTPException(status_code=400, detail="'action' field required.")

    try:
        state, reward, done, _info = _env.step(action)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    _current_obs = state
    _step_count  = state.get("step_count", _step_count + 1)

    return {
        "observation": _make_observation(state),
        "reward":      reward,
        "done":        done,
    }


@app.get("/state")
def get_state():
    """
    Return current environment state (read-only).
    Matches openenv-core State dataclass: {episode_id, step_count}.
    """
    return {
        "episode_id": None,
        "step_count": _step_count,
        "task":       _current_task,
    }


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=7860, reload=False)
