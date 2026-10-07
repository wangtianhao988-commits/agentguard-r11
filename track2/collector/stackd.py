"""Per-call stack capture, from outside the protected process.

The claim this replaces
-----------------------
Earlier in this project the audit concluded that "应用内函数栈不可恢复" -- no logging,
no OpenTelemetry, no middleware, no traceback capture anywhere in the range, and
`/admin/trajectories` is off limits by the brief. That conclusion was correct about
**recovering stacks from logs after the fact** and wrong as a general statement.

The range does not record stacks. It does not have to: the process is alive, and a
stack can be read from it. `py-spy` attaches through `SYS_PTRACE` and dumps real Python
frames without importing anything into the target.

Why this is deterministic rather than statistical
-------------------------------------------------
A profiler samples and hopes to catch the interesting moment. Here the moment is
known: **when the guard intercepts a `tools/call`, the protected application is
blocked waiting for that very HTTP response.** Its stack at that instant is not a
sample of typical behaviour -- it is exactly the call chain that produced the action
under judgement:

    call_mcp  <- run_tool_calls  <- run_stub_agent  <- run_agent  <- starlette

So the capture is issued at the decision point and is expected to contain the chain.

Cost is kept off the benign path
--------------------------------
A `py-spy dump` costs **10–15 ms** as measured on this deployment (an earlier comment
here said "hundreds of milliseconds" and was wrong by more than an order of magnitude).
Even at 15 ms it is too much to pay per request against a one-second budget, so the
capture runs **only when there is a finding**, and **synchronously, before the response
leaves**.

Synchronous is the part that matters and the first attempt got it wrong. Capturing in
a background task after forwarding produced the IDLE worker's stack: py-spy attached a
few milliseconds later, by which time the application had its response and had gone
back to waiting for work. **The window in which the stack is meaningful is exactly the
window in which the application is blocked on us** -- i.e. before we answer.

    GET /stack          -> {"threads": [...], "took_ms": ..., "pid": 1}
    GET /health         -> {"ok": true}
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI

app = FastAPI(title="agentrange-stack-capture")

TARGET_PID = int(os.getenv("TARGET_PID", "1"))
PYSPY = os.getenv("PYSPY_BIN", "py-spy")
TIMEOUT = float(os.getenv("STACK_TIMEOUT", "5"))
#: Frames belonging to the framework are kept -- they are the point -- but the
#: response is trimmed so one capture cannot dominate an audit record. 24 stopped at
#: `run_tool_calls`, one frame short of `run_agent`; 40 carries the whole chain from
#: the socket read down to the entry point.
MAX_FRAMES = int(os.getenv("STACK_MAX_FRAMES", "40"))

#: Frames from the guard's OWN machinery, which would otherwise appear in every
#: capture and tell a reader nothing about the application.
_NOISE = ("py_spy", "py_spy_", "threading.py", "queue.py")


def _dump() -> Dict[str, Any]:
    t0 = time.perf_counter()
    try:
        p = subprocess.run([PYSPY, "dump", "--pid", str(TARGET_PID), "--json"],
                           capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"error": "py-spy timed out", "took_ms": (time.perf_counter() - t0) * 1000}
    except FileNotFoundError:
        return {"error": "py-spy not installed", "took_ms": (time.perf_counter() - t0) * 1000}
    took = (time.perf_counter() - t0) * 1000

    if p.returncode != 0:
        return {"error": (p.stderr or "py-spy failed")[-300:], "took_ms": took,
                "returncode": p.returncode}
    try:
        raw = json.loads(p.stdout)
    except Exception as e:  # noqa: BLE001
        return {"error": f"unparseable py-spy output: {type(e).__name__}", "took_ms": took}

    threads: List[Dict[str, Any]] = []
    for t in raw if isinstance(raw, list) else [raw]:
        frames = []
        for fr in (t.get("frames") or [])[:MAX_FRAMES]:
            name = fr.get("name", "")
            fn = fr.get("filename") or fr.get("file") or ""
            line = fr.get("line", "")
            if any(n in fn for n in _NOISE):
                continue
            frames.append({"fn": name, "at": f"{os.path.basename(str(fn))}:{line}"})
        if frames:
            threads.append({"thread": t.get("thread_name") or t.get("name") or "?",
                            "active": t.get("active"), "frames": frames})

    # The application's own frames first: a reader wants `call_mcp`, not `starlette`.
    def score(th: Dict[str, Any]) -> int:
        return sum(1 for f in th["frames"] if f["at"].startswith("app.py"))

    threads.sort(key=score, reverse=True)
    return {"threads": threads, "took_ms": round(took, 1), "pid": TARGET_PID,
            "n_threads": len(threads)}


@app.get("/stack")
def stack() -> Dict[str, Any]:
    return _dump()


@app.get("/health")
def health() -> Dict[str, Any]:
    try:
        p = subprocess.run([PYSPY, "--version"], capture_output=True, text=True, timeout=5)
        return {"ok": p.returncode == 0, "version": (p.stdout or "").strip(),
                "target_pid": TARGET_PID}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "target_pid": TARGET_PID}
