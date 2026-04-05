"""Abstract base class for all vulnerability tasks."""

from abc import ABC, abstractmethod
from typing import Any, Dict, Tuple


class BaseTask(ABC):
    """
    Each task models a vulnerable system + its invariants.
    Subclasses implement the system, action handlers, and state.
    """

    TASK_ID: str = ""
    max_steps: int = 5

    @abstractmethod
    def apply_action(self, action: Dict) -> Any:
        """
        Apply a structured action to the system.
        Returns raw output (query results, rendered HTML, auth response, etc.)
        """

    @abstractmethod
    def evaluate(self) -> Tuple[float, Dict]:
        """
        Run the multi-signal evaluator.
        Returns (reward ∈ [0.0, 1.0], signals dict).
        """

    @abstractmethod
    def get_state(self) -> Dict:
        """
        Return a compact state dict for inclusion in the observation.
        Must be JSON-serializable and < a few KB.
        """
