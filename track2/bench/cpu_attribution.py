#!/usr/bin/env python
"""Where does the guard's CPU actually go?

Why measure instead of reasoning
--------------------------------
The audit concluded the M5 figure was "architecture cost -- the HTTP hop", based on
`forward_upstream` accounting for 97.5% of the guard's WALL time. **That inference was
wrong.** `await`-ing an upstream spends no CPU; it spends time. Attributing a CPU
number to a wall-clock share is exactly the kind of substitution this project has
already been burned by four times.

So: run a real replay, sample the container's CPU from the kernel, and separately
attribute it by turning features off one at a time. Anything that cannot be measured
this way is not claimed.

    python track2/bench/cpu_attribution.py --scenario all
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO = Path(__file__).resolve().parents[2]
RANGE = REPO / "_scratch" / "competition" / "agentrange"
CONTAINER = "agentrange-guard-gateway"


def _cpu_ns(name: str) -> Optional[int]:
    """Cumulative CPU nanoseconds from the kernel, for one container.

    Read from cgroup v2 `cpu.stat`, not from `docker stats`. `docker stats` reports a
    one-second average, which is useless for short phases and is the same source that
    produced the ambiguous 38.5% figure in the first place.
    """
    try:
        out = subprocess.run(
            ["docker", "exec", name, "cat", "/sys/fs/cgroup/cpu.stat"],
            capture_output=True, text=True, timeout=15)
        m = re.search(r"usage_usec\s+(\d+)", out.stdout)
        if m:
            return int(m.group(1)) * 1000
    except Exception:  # noqa: BLE001
        pass
    return None


def _proc_cpu_ns(name: str) -> Optional[int]:
    """Fallback: sum /proc/<pid>/stat utime+stime across every process in the container."""
    try:
        out = subprocess.run(
            ["docker", "exec", name, "sh", "-c",
             "for p in /proc/[0-9]*; do awk '{print $14+$15}' $p/stat 2>/dev/null; done"],
            capture_output=True, text=True, timeout=15)
        ticks = sum(int(x) for x in out.stdout.split() if x.isdigit())
        return ticks * 10_000_000  # USER_HZ = 100 -> 10 ms per tick
    except Exception:  # noqa: BLE001
        return None


def run_replay(scenario: str, env_extra: Dict[str, str]) -> Tuple[float, int]:
    """Run one replay, return (wall seconds, guard CPU seconds)."""
    import os
    env = dict(os.environ)
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
              "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        env.pop(k, None)
    env.update({"OPSPILOT_BASE": "http://localhost:8101",
                "LANGFLOW_BASE": "http://localhost:8101/langflow"})
    env.update(env_extra)

    # Restart the guard so the env changes take effect and counters start clean.
    subprocess.run(["docker", "compose", "up", "-d", "--force-recreate", "guard-gateway"],
                   cwd=str(RANGE), capture_output=True, text=True, timeout=300,
                   env={**env, **{k: "" for k in ("HTTP_PROXY", "HTTPS_PROXY",
                                                  "ALL_PROXY", "NO_PROXY")}})
    time.sleep(8)

    before = _cpu_ns(CONTAINER) or _proc_cpu_ns(CONTAINER) or 0
    t0 = time.perf_counter()
    p = subprocess.run(["powershell", "-NoProfile", "-Command",
                        f".\\run_range.ps1 scenario-runner\\runner.py {scenario}"],
                       cwd=str(RANGE), capture_output=True, text=True,
                       timeout=3600, env=env)
    wall = time.perf_counter() - t0
    after = _cpu_ns(CONTAINER) or _proc_cpu_ns(CONTAINER) or 0
    return wall, max(0.0, (after - before) / 1e9)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="all")
    ap.add_argument("--modes", default="observe,norecord,nojson")
    a = ap.parse_args()

    # Each mode disables exactly one cost, so the delta attributes it.
    modes = {
        "observe":  {"RECORD_ENABLED": "1"},   # full guard: parse + record + forward
        "norecord": {"RECORD_ENABLED": "0"},   # forward only: isolates evidence writing
    }
    wanted = [m.strip() for m in a.modes.split(",") if m.strip() in modes]

    print("=" * 100)
    print("GUARD CPU ATTRIBUTION -- measured, not inferred")
    print("=" * 100)
    print(f"  scenario: {a.scenario}")
    print()

    results: Dict[str, Dict[str, float]] = {}
    for mode in wanted:
        print(f"  running mode '{mode}' ...", flush=True)
        wall, cpu = run_replay(a.scenario, modes[mode])
        results[mode] = {"wall_s": wall, "cpu_s": cpu}
        print(f"     wall {wall:8.1f}s   guard CPU {cpu:7.1f}s   "
              f"= {100 * cpu / wall:5.1f}% of one core")

    print()
    print("-" * 100)
    if "observe" in results and "norecord" in results:
        o, n = results["observe"], results["norecord"]
        if o["wall_s"] > 0 and n["wall_s"] > 0:
            d = 100 * (o["cpu_s"] / o["wall_s"] - n["cpu_s"] / n["wall_s"])
            print(f"  evidence writing costs ~{d:.1f} percentage points of one core.")
            print(f"  Everything else ({100 * n['cpu_s'] / n['wall_s']:.1f}%) is "
                  f"proxy + parse, i.e. what remains even with recording off.")
    print()
    print("  Read this column by column: the number that matters for M5 is the guard's")
    print("  own share at the request rate the judge will actually drive.")
    print("=" * 100)
    out = REPO / "track2" / "bench" / "cpu_attribution.json"
    out.write_text(json.dumps(results, indent=1), encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
