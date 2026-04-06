"""
validate.py  –  Pre-submission validation script.

Checks every requirement from the submission checklist:

  [1] openenv.yaml      – exists and has required fields
  [2] Dockerfile        – exists
  [3] inference.py      – exists at repo root, uses OpenAI client, correct env vars
  [4] requirements.txt  – exists, includes openai
  [5] Env vars          – API_BASE_URL, MODEL_NAME, HF_TOKEN defined
  [6] Environment API   – reset() / step() / state() work correctly
  [7] 3+ tasks          – each task produces a reward in [0.0, 1.0]
  [8] Reward range      – all rewards normalised and deterministic

Run:
    python validate.py
"""

import importlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS  = "\033[92m[PASS]\033[0m"
FAIL  = "\033[91m[FAIL]\033[0m"
WARN  = "\033[93m[WARN]\033[0m"
INFO  = "\033[94m[INFO]\033[0m"

errors   = 0
warnings = 0


def ok(msg):
    print(f"  {PASS} {msg}")

def fail(msg):
    global errors
    errors += 1
    print(f"  {FAIL} {msg}")

def warn(msg):
    global warnings
    warnings += 1
    print(f"  {WARN} {msg}")

def info(msg):
    print(f"  {INFO} {msg}")

def section(title):
    print(f"\n── {title} {'─' * (55 - len(title))}")


# ── [1] openenv.yaml ──────────────────────────────────────────────────────────
section("1. openenv.yaml")

if not os.path.exists("openenv.yaml"):
    fail("openenv.yaml not found")
else:
    ok("openenv.yaml exists")
    try:
        import yaml
        with open("openenv.yaml") as f:
            spec = yaml.safe_load(f)
        required_keys = ["name", "version", "tasks", "action_space", "observation_space", "reward"]
        for k in required_keys:
            if k in spec:
                ok(f"  field '{k}' present")
            else:
                fail(f"  field '{k}' missing from openenv.yaml")
        tasks = spec.get("tasks", [])
        if len(tasks) >= 3:
            ok(f"  {len(tasks)} tasks defined (≥ 3 required)")
        else:
            fail(f"  only {len(tasks)} task(s) defined — need ≥ 3")
    except ImportError:
        warn("pyyaml not installed — skipping yaml field validation (pip install pyyaml)")
    except Exception as e:
        fail(f"  failed to parse openenv.yaml: {e}")


# ── [2] Dockerfile ────────────────────────────────────────────────────────────
section("2. Dockerfile")

if not os.path.exists("Dockerfile"):
    fail("Dockerfile not found")
else:
    ok("Dockerfile exists")
    content = open("Dockerfile").read()
    if "7860" in content:
        ok("  port 7860 exposed (required for HF Spaces)")
    else:
        fail("  port 7860 not found in Dockerfile")
    if "uvicorn" in content or "CMD" in content:
        ok("  CMD/entrypoint present")
    else:
        fail("  no CMD found in Dockerfile")


# ── [3] inference.py ─────────────────────────────────────────────────────────
section("3. inference.py")

if not os.path.exists("inference.py"):
    fail("inference.py not found at repo root")
else:
    ok("inference.py exists at repo root")
    src = open("inference.py").read()

    if "from openai import OpenAI" in src or "import openai" in src:
        ok("  uses OpenAI client")
    else:
        fail("  OpenAI client not found — must use 'from openai import OpenAI'")

    for var in ("API_BASE_URL", "MODEL_NAME", "HF_TOKEN"):
        if var in src:
            ok(f"  env var {var} referenced")
        else:
            fail(f"  env var {var} not referenced in inference.py")

    for tag in ("[START]", "[STEP]", "[END]", "final_reward"):
        if tag in src:
            ok(f"  log tag '{tag}' present")
        else:
            fail(f"  log tag '{tag}' missing from inference.py")


# ── [4] requirements.txt ──────────────────────────────────────────────────────
section("4. requirements.txt")

if not os.path.exists("requirements.txt"):
    fail("requirements.txt not found")
else:
    ok("requirements.txt exists")
    reqs = open("requirements.txt").read().lower()
    if "openai" in reqs:
        ok("  openai listed")
    else:
        fail("  openai missing from requirements.txt")
    if "fastapi" in reqs:
        ok("  fastapi listed (needed for HF Space)")
    else:
        warn("  fastapi not in requirements.txt — needed for app.py / HF Space")
    if "uvicorn" in reqs:
        ok("  uvicorn listed")
    else:
        warn("  uvicorn not in requirements.txt — needed to serve app.py")


# ── [5] Env vars ──────────────────────────────────────────────────────────────
section("5. Environment variables")

# Load .env if present
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(_env_path):
    with open(_env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
    info(".env loaded")

for var in ("API_BASE_URL", "MODEL_NAME", "HF_TOKEN"):
    val = os.environ.get(var, "")
    if val:
        # Mask token value
        display = val if var != "HF_TOKEN" else val[:8] + "..." + val[-4:]
        ok(f"  {var} = {display}")
    else:
        fail(f"  {var} is not set")


# ── [6 & 7] Environment API + tasks ──────────────────────────────────────────
section("6 & 7. Environment API + task graders (≥ 3 tasks, rewards in [0,1])")

try:
    from env import VulnEnv
    env = VulnEnv()
    ok("VulnEnv imported successfully")

    task_ids = env.task_ids
    if len(task_ids) >= 3:
        ok(f"  {len(task_ids)} tasks available: {task_ids}")
    else:
        fail(f"  only {len(task_ids)} task(s) — need ≥ 3")

    # Probe payloads — correct tool for phase/step 1 of each task
    PROBES = {
        "sql_injection":           {"type": "select", "target": "send_request",           "payload": "'"},
        "spearphish_credential":   {"type": "select", "target": "craft_delivery",         "payload": ""},
        "cloud_identity_intrusion":{"type": "select", "target": "probe_accounts",         "payload": ""},
        "ai_tool_exploitation":    {"type": "select", "target": "probe_via_benign_task",  "payload": ""},
    }

    for task_id in task_ids:
        state = env.reset(task_id)

        # reset() must return a dict with required fields
        for field in ("task", "code_context", "signals", "step_count"):
            if field not in state:
                fail(f"  [{task_id}] reset() state missing field '{field}'")

        ok(f"  [{task_id}] reset() returned valid state")

        probe = PROBES.get(task_id, {"type": "input", "target": "query", "payload": "test"})
        state2, reward, done, info_dict = env.step(probe)

        # Reward must be in [0, 1]
        if not (0.0 <= reward <= 1.0):
            fail(f"  [{task_id}] reward {reward} out of [0.0, 1.0]")
        else:
            ok(f"  [{task_id}] step() reward = {reward:.4f} ∈ [0.0, 1.0]")

        # done must be bool
        if not isinstance(done, bool):
            fail(f"  [{task_id}] done is not bool: {type(done)}")
        else:
            ok(f"  [{task_id}] done = {done} (bool)")

        # Determinism check — same action, same reward
        env.reset(task_id)
        _, reward2, _, _ = env.step(probe)
        if reward == reward2:
            ok(f"  [{task_id}] deterministic (same action → same reward)")
        else:
            fail(f"  [{task_id}] non-deterministic: {reward} ≠ {reward2}")

except Exception as e:
    fail(f"Environment validation error: {e}")
    import traceback; traceback.print_exc()


# ── [8] app.py (HF Space server) ──────────────────────────────────────────────
section("8. app.py (HF Space server)")

if not os.path.exists("app.py"):
    fail("app.py not found — required for HF Space /health ping")
else:
    ok("app.py exists")
    src = open("app.py").read()
    for endpoint in ("/health", "/reset", "/step", "/state"):
        if endpoint in src:
            ok(f"  endpoint '{endpoint}' defined")
        else:
            fail(f"  endpoint '{endpoint}' missing from app.py")
    if "7860" in src:
        ok("  port 7860 present")
    else:
        warn("  port 7860 not found in app.py")


# ── Summary ───────────────────────────────────────────────────────────────────
section("Summary")
print(f"\n  Errors:   {errors}")
print(f"  Warnings: {warnings}")

if errors == 0 and warnings == 0:
    print(f"\n  {PASS} All checks passed — ready to submit!\n")
elif errors == 0:
    print(f"\n  {WARN} No errors, but {warnings} warning(s) — review before submitting.\n")
else:
    print(f"\n  {FAIL} {errors} error(s) found — fix before submitting.\n")

sys.exit(0 if errors == 0 else 1)
