"""
Validates and normalises incoming action dicts before they reach a task.

Action schema
-------------
{
    "type"    : "input" | "edit",
    "target"  : str,          # endpoint / function name
    "payload" : str           # injection string or diff/mutation
}
"""

from typing import Dict

VALID_TYPES = {"input", "edit", "select"}
MAX_PAYLOAD_LEN = 2048   # hard cap to prevent abuse


class ActionParseError(ValueError):
    pass


def parse_action(raw: Dict) -> Dict:
    """
    Validate and normalise a raw action dict.

    Raises ActionParseError on invalid input so env.step() can return a
    clean error reward instead of crashing.
    """
    if not isinstance(raw, dict):
        raise ActionParseError(f"Action must be a dict, got {type(raw).__name__}")

    action_type = raw.get("type")
    if action_type not in VALID_TYPES:
        raise ActionParseError(
            f"Unknown action type {action_type!r}. Valid: {sorted(VALID_TYPES)}"
        )

    target = str(raw.get("target", "")).strip()
    payload = str(raw.get("payload", "")).strip()

    if len(payload) > MAX_PAYLOAD_LEN:
        raise ActionParseError(
            f"Payload too long ({len(payload)} > {MAX_PAYLOAD_LEN} chars)"
        )

    return {"type": action_type, "target": target, "payload": payload}
