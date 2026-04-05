"""Base evaluator interface."""

from abc import ABC, abstractmethod
from typing import Tuple, Dict


class BaseEvaluator(ABC):
    """
    Multi-signal evaluator contract.
    Each evaluator grades one task across four signal types.
    """

    # Signal weights must sum to 1.0
    W_EXPLOIT   = 0.60   # Primary: did the exploit succeed?
    W_PARTIAL   = 0.25   # Intermediate: suspicious patterns / partial progress
    W_INTEGRITY = 0.15   # System still functional (no crash / invalid state)

    @classmethod
    @abstractmethod
    def evaluate(cls, task) -> Tuple[float, Dict]:
        """
        Grade the current task state.

        Returns
        -------
        reward : float   – deterministic score in [0.0, 1.0]
        signals : dict   – {exploit_success, partial_score, integrity_ok, reward}
        """
