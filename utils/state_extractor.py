"""
Builds the canonical observation dict returned from env.reset() / env.step().

Observation schema
------------------
{
    "task"          : str,
    "code_context"  : str,     # relevant snippet of vulnerable code
    "recent_action" : dict,    # last action taken (null on reset)
    "recent_output" : any,     # raw output of last action (null on reset)
    "signals"       : {
        "errors"  : str,
        "alerts"  : str,
        "hints"   : str
    },
    "step_count"    : int
}
"""

from typing import Any, Dict, Optional


def build_observation(
    task_id: str,
    task_state: Dict,
    step_count: int,
    recent_action: Optional[Dict] = None,
    recent_output: Any = None,
    signals: Optional[Dict] = None,
) -> Dict:
    """Assemble and truncate the observation to keep it compact."""

    code_ctx = task_state.get("code_context", "")
    # Hard-cap code context at 1 KB so state stays small
    if len(code_ctx) > 1024:
        code_ctx = code_ctx[:1024] + "\n... (truncated)"

    default_signals = {"errors": "", "alerts": "", "hints": task_state.get("hints", "")}
    merged_signals = {**default_signals, **(signals or {})}

    # Ensure signal values are strings
    for k in ("errors", "alerts", "hints"):
        merged_signals[k] = str(merged_signals.get(k, ""))

    return {
        "task": task_id,
        "code_context": code_ctx,
        "recent_action": recent_action,
        "recent_output": _truncate(recent_output),
        "signals": merged_signals,
        "step_count": step_count,
    }


def _truncate(value: Any, max_len: int = 512) -> Any:
    """Truncate string representations to keep state compact."""
    if value is None:
        return None
    s = str(value)
    if len(s) > max_len:
        return s[:max_len] + "... (truncated)"
    return value
