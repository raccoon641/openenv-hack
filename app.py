"""
app.py  –  FastAPI HTTP server wrapping VulnEnv for HuggingFace Space deployment.

Exposes the OpenEnv-compliant endpoints:
    GET  /health          → 200 {"status": "ok"}
    POST /reset           → initial state
    POST /step            → state, reward, done, info
    GET  /state           → current state (read-only)
    GET  /tasks           → list of available task IDs

HF Space URL: https://<your-space>.hf.space
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from env import VulnEnv

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="OpenEnv Vulnerability Environment",
    description="Injection-based vulnerability tasks: SQLi, Auth Bypass, XSS",
    version="1.0.0",
)

# Single environment instance (stateful, sequential use)
_env = VulnEnv()
_current_state: Optional[Dict] = None


# ── Request / Response models ─────────────────────────────────────────────────

class ResetRequest(BaseModel):
    task: str


class StepRequest(BaseModel):
    action: Dict[str, Any]


class ResetResponse(BaseModel):
    state: Dict[str, Any]


class StepResponse(BaseModel):
    state:  Dict[str, Any]
    reward: float
    done:   bool
    info:   Dict[str, Any]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    """Liveness probe — must return 200 for HF Space ping check."""
    return {"status": "ok", "tasks": _env.task_ids}


@app.get("/tasks")
def list_tasks():
    """Return all available task IDs."""
    return {"tasks": _env.task_ids}


@app.post("/reset", response_model=ResetResponse)
def reset(req: ResetRequest):
    """
    Reset the environment to the start of the given task.
    Returns the initial observation state.
    """
    global _current_state
    try:
        state = _env.reset(req.task)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    _current_state = state
    return {"state": state}


@app.post("/step", response_model=StepResponse)
def step(req: StepRequest):
    """
    Apply a structured action and advance the episode.
    Returns next state, reward, done flag, and diagnostic info.
    """
    global _current_state
    if _current_state is None:
        raise HTTPException(
            status_code=400,
            detail="Environment not initialised. Call POST /reset first."
        )
    try:
        state, reward, done, info = _env.step(req.action)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    _current_state = state
    return {"state": state, "reward": reward, "done": done, "info": info}


@app.get("/state")
def get_state():
    """Return the current observation without advancing the episode."""
    if _current_state is None:
        raise HTTPException(
            status_code=400,
            detail="Environment not initialised. Call POST /reset first."
        )
    return {"state": _current_state}


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    # HF Spaces requires port 7860
    uvicorn.run("app:app", host="0.0.0.0", port=7860, reload=False)
