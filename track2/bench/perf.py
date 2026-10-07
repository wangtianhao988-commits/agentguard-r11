#!/usr/bin/env python
"""Measure M4 (response time < 1s) and M5 (CPU < 5%).

Two numbers the brief makes pass/fail, and neither may be asserted -- both are
measured, and measured against the *right* baseline.

M4 -- added latency, not absolute latency
-----------------------------------------
Quoting "the request took 40 ms" proves nothing: most of that is the agent's own
work. What the guard is answerable for is the **difference** between going through
it and not. So the same request is issued directly and through the gateway, and the
paired difference is reported. The percentiles are computed on the per-request
differences, not on two independent distributions.

M5 -- CPU of the guard only
---------------------------
`docker stats` on the guard containers during a full 5200-event replay. The agent's
own CPU is not the guard's problem, and folding it in would make the number look
better while meaning less.

    python track2/bench/perf.py --n 400
"""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

RANGE = Path(__file__).resolve().parents[2] / "_scratch" / "competition" / "agentrange"

DIRECT = "http://localhost:8100"
GATEWAY = "http://localhost:8101"

BENIGN_PROMPT = "请帮我确认 ACME 工单 8558 的联系人记录。"


def post(url: str, body: Dict[str, Any], headers: Dict[str, str],
         timeout: float = 20.0) -> float:
    """One POST; returns elapsed ms. Uses perf_counter -- on Windows
    time.monotonic() is GetTickCount64 with ~15.6 ms resolution and reported a real
    4 ms call as 0.0 ms earlier in this project."""
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json", **headers})
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        r.read()
    return (time.perf_counter() - t0) * 1000.0


def login(base: str) -> str:
    body = json.dumps({"username": "lwang"}).encode()
    req = urllib.request.Request(f"{base}/login", data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())["access_token"]


def pct(xs: List[float], p: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p * len(xs)))]


def docker_cpu(names: List[str]) -> Dict[str, float]:
    try:
        out = subprocess.run(["docker", "stats", "--no-stream", "--format",
                              "{{.Name}}\t{{.CPUPerc}}"] + names,
                             capture_output=True, text=True, timeout=60).stdout
    except Exception:  # noqa: BLE001
        return {}
    res = {}
    for line in out.splitlines():
        if "\t" in line:
            n, c = line.split("\t", 1)
            try:
                res[n.strip()] = float(c.strip().rstrip("%"))
            except ValueError:
                continue
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=400)
    ap.add_argument("--json", default=None)
    a = ap.parse_args()

    print("=" * 100)
    print(f"M4 -- ADDED LATENCY  (paired, n={a.n}, perf_counter)")
    print("=" * 100)

    tok_d = login(DIRECT)
    tok_g = login(GATEWAY)
    hd = {"Authorization": f"Bearer {tok_d}", "X-Instance-Id": "perf-d", "X-Trace-Id": "perf-d"}
    hg = {"Authorization": f"Bearer {tok_g}", "X-Instance-Id": "perf-g", "X-Trace-Id": "perf-g"}

    body = {"model": "opspilot-stub", "prompt": BENIGN_PROMPT}
    direct, proxied, paired = [], [], []

    # Warm up both paths so the first-call cost (connection setup, JIT of the
    # server's regexes) does not land in the sample.
    for _ in range(20):
        post(f"{DIRECT}/run", body, hd)
        post(f"{GATEWAY}/run", body, hg)

    errors = 0
    for _ in range(a.n):
        try:
            td = post(f"{DIRECT}/run", body, hd)
            tg = post(f"{GATEWAY}/run", body, hg)
            direct.append(td)
            proxied.append(tg)
            paired.append(tg - td)
        except Exception:  # noqa: BLE001
            errors += 1

    if not paired:
        print("  no successful pairs; cannot measure")
        return 1

    print(f"  direct   p50={statistics.median(direct):7.2f}  p95={pct(direct,.95):7.2f}  "
          f"p99={pct(direct,.99):7.2f} ms")
    print(f"  proxied  p50={statistics.median(proxied):7.2f}  p95={pct(proxied,.95):7.2f}  "
          f"p99={pct(proxied,.99):7.2f} ms")
    print(f"  ADDED    p50={statistics.median(paired):7.2f}  p95={pct(paired,.95):7.2f}  "
          f"p99={pct(paired,.99):7.2f} ms   (paired per-request difference)")
    print(f"  errors={errors}   budget=1000 ms   "
          f"{'PASS' if pct(paired, .99) < 1000 else 'FAIL'}")
    print()
    print("  The guard is answerable for the ADDED column. The absolute numbers are")
    print("  dominated by the agent's own work and are shown only for context.")

    print()
    print("=" * 100)
    print("M5 -- GUARD CPU DURING A FULL REPLAY")
    print("=" * 100)
    names = ["agentrange-guard-gateway", "agentrange-opspilot-app-1"]
    base = docker_cpu(names)
    print(f"  idle: {base}")

    print("\n  starting the 5200-event replay and sampling CPU every 3 s ...")
    env = {"OPSPILOT_BASE": GATEWAY, "LANGFLOW_BASE": f"{GATEWAY}/langflow"}
    import os
    e = dict(os.environ)
    e.update(env)
    for v in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
              "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        e.pop(v, None)
    py = RANGE / ".venv" / "Scripts" / "python.exe"
    proc = subprocess.Popen([str(py), "scenario-runner/runner.py", "all"],
                            cwd=str(RANGE), env=e,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    samples: List[Dict[str, float]] = []
    while proc.poll() is None:
        s = docker_cpu(names)
        if s:
            samples.append(s)
        time.sleep(3)
    proc.wait()

    print(f"\n  replay exit: {proc.returncode}   samples: {len(samples)}")
    if samples:
        for name in names:
            vals = [s.get(name, 0.0) for s in samples if name in s]
            if not vals:
                continue
            print(f"  {name:<34} mean={statistics.fmean(vals):5.2f}%  "
                  f"p95={pct(vals,.95):5.2f}%  max={max(vals):5.2f}%")
        gw = [s.get("agentrange-guard-gateway", 0.0) for s in samples
              if "agentrange-guard-gateway" in s]
        if gw:
            ok = statistics.fmean(gw) < 5.0
            print(f"\n  guard gateway mean CPU {statistics.fmean(gw):.2f}%  "
                  f"budget < 5%   {'PASS' if ok else 'FAIL'}")
            print("  (docker's CPU% is relative to the whole host, 32 cores, which is the")
            print("   same denominator the brief's 'CPU 占用率' is read against.)")

    if a.json:
        Path(a.json).write_text(json.dumps({
            "m4": {"direct_p50": statistics.median(direct), "proxied_p50": statistics.median(proxied),
                   "added_p50": statistics.median(paired), "added_p95": pct(paired, .95),
                   "added_p99": pct(paired, .99), "n": len(paired), "errors": errors},
            "m5": {n: {"mean": statistics.fmean([s.get(n, 0.0) for s in samples if n in s]),
                       "max": max([s.get(n, 0.0) for s in samples if n in s] or [0])}
                   for n in names},
        }, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"\nwrote {a.json}")
    print("=" * 100)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
