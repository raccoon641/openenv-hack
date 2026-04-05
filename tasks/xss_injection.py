"""
Task: XSS / Output Injection
=============================
System  : A minimal server-side template renderer that builds an HTML page
          by directly interpolating user-supplied values into a template
          string — no escaping, no sanitisation.
Surface : The 'username' and 'message' fields passed to the renderer.
Invariant: The rendered HTML must not contain executable <script> tags or
           event-handler attributes (onclick, onerror, etc.).

Vulnerable code (shown in observation)
---------------------------------------
    def render_profile(username: str, message: str) -> str:
        return (
            "<html><body>"
            f"<h1>Hello, {username}!</h1>"
            f"<p>{message}</p>"
            "</body></html>"
        )

Attack vectors
--------------
• username = "<script>alert('xss')</script>"
• message  = "<img src=x onerror=alert('xss')>"

Supported actions
-----------------
input  target="render"   payload="<username>::<message>"
    → Renders the page with username and message split on the first "::".
    → If "::" is absent the entire payload is used as username.

edit   target="render_profile"   payload="<raw HTML string>"
    → Sets the rendered output directly (simulates template mutation).
"""

import re
from typing import Any, Dict, Tuple

from .base import BaseTask


_VULNERABLE_CODE = """\
def render_profile(username: str, message: str) -> str:
    # ⚠️  No HTML escaping — vulnerable to XSS
    return (
        "<html><body>"
        f"<h1>Hello, {username}!</h1>"
        f"<p>{message}</p>"
        "</body></html>"
    )
"""

# Patterns that constitute a successful XSS exploit
_SCRIPT_RE   = re.compile(r"<script[\s>]", re.IGNORECASE)
_HANDLER_RE  = re.compile(r"\bon\w+\s*=", re.IGNORECASE)   # onclick=, onerror=, …
_HREF_JS_RE  = re.compile(r"href\s*=\s*['\"]?\s*javascript:", re.IGNORECASE)

# Patterns that indicate partial/probing injection (HTML but not yet executable)
_HTML_TAG_RE = re.compile(r"<[a-zA-Z/][^>]*>")


class XSSInjectionTask(BaseTask):
    TASK_ID = "xss_injection"
    max_steps = 5

    # ------------------------------------------------------------------ #
    #  Setup                                                               #
    # ------------------------------------------------------------------ #

    def __init__(self):
        self.render_log: list[str] = []  # all rendered HTML outputs
        self.payload_log: list[str] = []  # all raw payloads received
        self.last_output: str = ""
        self.last_error: str = ""
        self.exploit_triggered: bool = False

    # ------------------------------------------------------------------ #
    #  Vulnerable renderer                                                 #
    # ------------------------------------------------------------------ #

    def _render_profile(self, username: str, message: str = "") -> str:
        # ⚠️  Intentional vulnerability: no HTML escaping
        return (
            "<html><body>"
            f"<h1>Hello, {username}!</h1>"
            f"<p>{message}</p>"
            "</body></html>"
        )

    # ------------------------------------------------------------------ #
    #  Action handler                                                      #
    # ------------------------------------------------------------------ #

    def apply_action(self, action: Dict) -> Any:
        atype   = action.get("type", "")
        payload = action.get("payload", "")
        target  = action.get("target", "")
        self.last_error = ""

        if atype == "input" and "render" in target:
            # Split on "::" to allow separate username / message injection
            if "::" in payload:
                username, message = payload.split("::", 1)
            else:
                username, message = payload, ""
            rendered = self._render_profile(username.strip(), message.strip())
            self.render_log.append(rendered)
            self.payload_log.append(payload)
            result = {"rendered_html": rendered}

        elif atype == "edit" and "render" in target:
            # Direct HTML injection (simulates template code mutation)
            rendered = payload
            self.render_log.append(rendered)
            self.payload_log.append(payload)
            result = {"rendered_html": rendered}

        else:
            result = {"error": f"Unrecognised action type={atype!r} target={target!r}"}

        self.last_output = str(result.get("rendered_html", ""))

        # Detect exploit
        if self._is_exploit(self.last_output):
            self.exploit_triggered = True

        return result

    @staticmethod
    def _is_exploit(html: str) -> bool:
        return bool(
            _SCRIPT_RE.search(html)
            or _HANDLER_RE.search(html)
            or _HREF_JS_RE.search(html)
        )

    # ------------------------------------------------------------------ #
    #  Evaluator delegation                                                #
    # ------------------------------------------------------------------ #

    def evaluate(self) -> Tuple[float, Dict]:
        from evaluators.xss_evaluator import XSSEvaluator
        return XSSEvaluator.evaluate(self)

    # ------------------------------------------------------------------ #
    #  State (compact)                                                     #
    # ------------------------------------------------------------------ #

    def get_state(self) -> Dict:
        return {
            "code_context": _VULNERABLE_CODE,
            "hints": (
                "The renderer interpolates user input directly into HTML. "
                "Try injecting a <script> tag or an event handler attribute "
                "via the username or message field. "
                "Use 'payload' format: 'username::message'."
            ),
        }
