"""
OpenEnv Vulnerability Environment
===================================
Implements the OpenEnv interface:

    env = VulnEnv()
    state          = env.reset(task_id)
    state, r, done, info = env.step(action)

Tasks
-----
    "sql_injection"  – SQLi via unsanitised string formatting
    "auth_bypass"    – Auth bypass via Python eval injection
    "xss_injection"  – XSS via unescaped HTML template rendering

Action schema
-------------
    {"type": "input"|"edit", "target": str, "payload": str}

Observation schema
------------------
    {
        "task":          str,
        "code_context":  str,
        "recent_action": dict | None,
        "recent_output": any  | None,
        "signals": {
            "errors":  str,
            "alerts":  str,
            "hints":   str
        },
        "step_count": int
    }

Reward
------
    float ∈ [0.0, 1.0], deterministic per (task, action_sequence)
"""

from typing import Any, Dict, Optional, Tuple

from tasks      import TASK_REGISTRY
from tasks.base import BaseTask
from utils      import parse_action, ActionParseError, build_observation


class VulnEnv:
    """OpenEnv-compatible vulnerability environment."""

    def __init__(self):
        self._task_id:       Optional[str]      = None
        self._task:          Optional[BaseTask]  = None
        self._step_count:    int                 = 0
        self._done:          bool                = False
        self._recent_action: Optional[Dict]      = None

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    @property
    def task_ids(self) -> list[str]:
        """List of available task IDs."""
        return list(TASK_REGISTRY.keys())

    def reset(self, task: str) -> Dict:
        """
        Initialise (or re-initialise) the environment for the given task.

        Parameters
        ----------
        task : str  – one of self.task_ids

        Returns
        -------
        Initial observation dict.
        """
        if task not in TASK_REGISTRY:
            raise ValueError(
                f"Unknown task {task!r}. Available: {self.task_ids}"
            )

        self._task_id       = task
        self._task          = TASK_REGISTRY[task]()
        self._step_count    = 0
        self._done          = False
        self._recent_action = None

        return self._observe(signals=None, recent_output=None)

    def step(self, action: Dict) -> Tuple[Dict, float, bool, Dict]:
        """
        Apply a structured action and advance the episode by one step.

        Parameters
        ----------
        action : dict  – {"type": ..., "target": ..., "payload": ...}

        Returns
        -------
        (observation, reward, done, info)
            observation : dict  – next state
            reward      : float – ∈ [0.0, 1.0]
            done        : bool  – True when episode terminates
            info        : dict  – diagnostic signals + metadata
        """
        self._assert_ready()

        # ── Parse & validate action ──────────────────────────────────────
        try:
            clean_action = parse_action(action)
        except ActionParseError as exc:
            obs = self._observe(
                signals={"errors": str(exc), "alerts": "", "hints": ""},
                recent_output=None,
            )
            return obs, 0.0, False, {"error": str(exc)}

        self._recent_action = clean_action

        # ── Apply action to task ─────────────────────────────────────────
        output = self._task.apply_action(clean_action)
        self._step_count += 1

        # ── Evaluate ─────────────────────────────────────────────────────
        reward, signals = self._task.evaluate()

        # ── Termination ──────────────────────────────────────────────────
        self._done = (
            signals.get("exploit_success", False)
            or self._step_count >= self._task.max_steps
        )

        obs = self._observe(signals=signals, recent_output=output)

        info = {
            "task":            self._task_id,
            "step_count":      self._step_count,
            "max_steps":       self._task.max_steps,
            "exploit_success": signals.get("exploit_success", False),
            "partial_score":   signals.get("partial_score", 0.0),
            "integrity_ok":    signals.get("integrity_ok", True),
            "reward":          reward,
            "done":            self._done,
        }
        return obs, reward, self._done, info

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _assert_ready(self):
        if self._task is None:
            raise RuntimeError("Call reset(task_id) before step().")
        if self._done:
            raise RuntimeError("Episode is done. Call reset() to start a new one.")

    def _observe(
        self,
        signals: Optional[Dict],
        recent_output: Any,
    ) -> Dict:
        task_state = self._task.get_state()
        return build_observation(
            task_id       = self._task_id,
            task_state    = task_state,
            step_count    = self._step_count,
            recent_action = self._recent_action,
            recent_output = recent_output,
            signals       = signals,
        )
