"""M5: what does the HTTP hop actually cost?

The question
------------
`docker stats` reads the guard at 38.5% against a 5% requirement. That reading divides by
ONE core, and the number this project reports alongside it -- 1.20%, normalised to 32 --
is not a reading any tool would display. So there are two numbers and neither settles it.

Three explanations were proposed for the 38.5% and all three were refuted by measurement:
"97.5% of it is the HTTP hop" (that was wall-clock read as CPU), "it is evidence writing"
(0.2 pp for 27% of the bytes), "it is a small connection pool" (20 -> 128 changed it from
38.0% to 38.1%). `py-spy` gives a flat profile -- largest single frame 15.5%, the asyncio
event loop -- which is the signature of per-request runtime overhead, not a hot spot.

So the remaining question is not "where is the hot spot" but "how much of this is the
architecture", and the only way to answer that is to run the same workload both ways.

What is measured
----------------
The same MCP calls, twice:

  A. gateway mode    -- agent -> gateway -> mcp server. The gateway's CPU and the MCP
                        server's CPU are summed, because together they do the work.
  B. in-process mode -- agent -> mcp server, detector inside the server process.
                        One container's CPU.

**Both totals are read the same way**, with `docker stats --no-stream`, which is the tool
whose denominator the requirement is being judged against. Reporting A with one tool and
B with another would make the comparison meaningless, and that is the mistake the 1.20%
figure already made once.

Scope: one MCP server, one call shape, repeated. This is a controlled comparison, not a
whole-range load test, and it says nothing about the other seven servers.

    python track2/bench/m5_inprocess.py --calls 400
"""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Dict, List

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
RANGE = REPO / "_scratch" / "competition" / "agentrange"

GATEWAY = "http://localhost:8101"
SERVER_CONTAINER = "agentrange-mcp-customer-db-1"
GATEWAY_CONTAINER = "agentrange-guard-gateway"


def _cpu_usec(container: str) -> float:
    """CPU consumed by the container, in microseconds, straight from the cgroup.

    **Better than `docker stats` for this comparison, and the reason matters.** Read
    live, `docker stats --no-stream` needs about a second to answer because it takes two
    readings internally; a run that finishes in 3.9 seconds yields three samples and
    misses the burst. Its first reading reported 0.14% for a proxy handling 513 calls a
    second, which is not a measurement of anything.

    The counter is exact and instant: the difference across the run divided by the wall
    time is the fraction of one core consumed -- the same denominator the 5% requirement
    uses and the same one `docker stats` displays. `docker stats` is still reported as a
    cross-check afterwards, so the two can be compared rather than one being trusted.
    """
    out = subprocess.run(
        ["docker", "exec", container, "cat", "/sys/fs/cgroup/cpu.stat"],
        capture_output=True, text=True, timeout=60)
    for line in (out.stdout or "").splitlines():
        if line.startswith("usage_usec"):
            try:
                return float(line.split()[1])
            except (IndexError, ValueError):
                return -1.0
    return -1.0


def _stats(container: str) -> float:
    """CPU % exactly as `docker stats` reports it: the single-core denominator."""
    out = subprocess.run(
        ["docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}", container],
        capture_output=True, text=True, timeout=60)
    txt = (out.stdout or "").strip().replace("%", "")
    try:
        return float(txt)
    except ValueError:
        return -1.0


def _call_direct(trace: str, tenant: str = "acme") -> int:
    """One call straight to the MCP server, bypassing the gateway."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "query", "arguments": {"tenant": tenant}}}).encode()
    # Port 8120 is published by docker-compose.inprocess.yml for exactly this. The
    # MCP servers publish nothing by default, so an earlier version of this function
    # pointed at localhost:8100 -- the AGENT -- and measured a service that was not the
    # one under test.
    req = urllib.request.Request("http://localhost:8120/mcp", data=body,
                                 headers={"content-type": "application/json",
                                          "x-trace-id": trace})
    try:
        return len(urllib.request.urlopen(req, timeout=30).read())
    except Exception:  # noqa: BLE001
        return 0


def _call_gateway(trace: str, tenant: str = "acme") -> int:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "query", "arguments": {"tenant": tenant}}}).encode()
    req = urllib.request.Request(f"{GATEWAY}/mcp/customer-db", data=body,
                                 headers={"content-type": "application/json",
                                          "x-trace-id": trace, "x-instance-id": trace})
    try:
        return len(urllib.request.urlopen(req, timeout=30).read())
    except Exception:  # noqa: BLE001
        return 0


def _load(calls: int, via_gateway: bool, workers: int = 16) -> Dict[str, float]:
    """Drive `calls` calls concurrently and read the cgroup counters across the run.

    **Concurrency is not optional here.** A sequential loop managed about 6.7 calls a
    second and produced readings of 0.09% and 0.15% -- both inside the noise floor, so the
    comparison would have been between two numbers indistinguishable from zero. The rate
    that matters is the one the guard was measured at in the first place, which needs
    parallel clients.

    **Counters rather than sampled percentages.** `docker stats --no-stream` takes about
    a second to answer, so a 3.9-second run yields three samples and misses the burst
    entirely. Reading `usage_usec` before and after and dividing by the wall time gives
    the fraction of one core consumed -- exact, and the same denominator. `docker stats`
    is read afterwards as a cross-check so the two can be compared rather than one
    trusted.
    """
    import threading

    done = threading.Semaphore(0)

    def caller(w: int) -> None:
        n = calls // workers + (1 if w < calls % workers else 0)
        for i in range(n):
            if via_gateway:
                _call_gateway(f"m5-{w}-{i}")
            else:
                _call_direct(f"m5-{w}-{i}")
        done.release()

    srv0 = _cpu_usec(SERVER_CONTAINER)
    gw0 = _cpu_usec(GATEWAY_CONTAINER) if via_gateway else 0.0
    time.sleep(0.5)
    srv0b = _cpu_usec(SERVER_CONTAINER)
    gw0b = _cpu_usec(GATEWAY_CONTAINER) if via_gateway else 0.0

    t0 = time.perf_counter()
    callers = [threading.Thread(target=caller, args=(w,), daemon=True)
               for w in range(workers)]
    for c in callers:
        c.start()
    for _ in callers:
        done.acquire()
    for c in callers:
        c.join(timeout=300)
    wall = time.perf_counter() - t0

    srv1 = _cpu_usec(SERVER_CONTAINER)
    gw1 = _cpu_usec(GATEWAY_CONTAINER) if via_gateway else 0.0

    # Idle draw measured just before the run, subtracted so the number is the cost of
    # THIS workload rather than of the container existing. The gauges were sampled over
    # 0.5 s of idle: the difference is what the container spends doing nothing.
    srv_idle = max(srv0b - srv0, 0.0) / 0.5 / 1e4      # % of one core while idle
    gw_idle = max(gw0b - gw0, 0.0) / 0.5 / 1e4 if via_gateway else 0.0

    def med(xs: List[float]) -> float:
        xs = [x for x in xs if x >= 0]
        return statistics.median(xs) if xs else -1.0

    # The workload's own cost: counter delta over wall time, minus the idle draw.
    srv_cpu = max((srv1 - srv0b) / max(wall, 1e-6) / 1e4 - srv_idle, 0.0)
    gw_cpu = (max((gw1 - gw0b) / max(wall, 1e-6) / 1e4 - gw_idle, 0.0)
              if via_gateway else 0.0)
    return {"server": srv_cpu, "gateway": gw_cpu,
            "server_idle": srv_idle, "gateway_idle": gw_idle,
            # `docker stats` as a cross-check, taken the same way for both modes so the
            # two figures can be compared rather than one being trusted.
            "stats_server": _stats(SERVER_CONTAINER),
            "stats_gateway": _stats(GATEWAY_CONTAINER) if via_gateway else 0.0,
            "wall_s": wall, "calls": calls,
            "rate": calls / max(wall, 0.001)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--calls", type=int, default=400)
    ap.add_argument("--mode", choices=["gateway", "inprocess", "both"], default="both")
    a = ap.parse_args()

    print("=" * 100)
    print("M5 -- the same workload through the gateway and in-process")
    print("=" * 100)
    print(f"  calls {a.calls} per mode; CPU sampled with `docker stats --no-stream`")
    print("  (the single-core denominator the requirement is judged against)")
    print()

    rows = {}
    if a.mode in ("gateway", "both"):
        print("  A. gateway mode -- agent -> gateway -> server ...")
        rows["gateway"] = _load(a.calls, True)
        r = rows["gateway"]
        print(f"     server {r['server']:.2f}%   gateway {r['gateway']:.2f}%   "
              f"wall {r['wall_s']:.1f}s")
    if a.mode in ("inprocess", "both"):
        print("  B. in-process mode -- agent -> server (detector inside) ...")
        rows["inprocess"] = _load(a.calls, False)
        r = rows["inprocess"]
        print(f"     server {r['server']:.2f}%   wall {r['wall_s']:.1f}s")

    print()
    print("-" * 100)
    if len(rows) == 2:
        g = rows["gateway"]
        p = rows["inprocess"]
        tot_g = g["server"] + g["gateway"]
        tot_p = p["server"]
        print(f"  gateway mode total   {tot_g:6.2f}%   (server {g['server']:.2f} "
              f"+ gateway {g['gateway']:.2f})")
        print(f"  in-process total     {tot_p:6.2f}%   (server {p['server']:.2f})")
        print()
        if tot_g > 0:
            print(f"  the hop costs {tot_g - tot_p:+.2f} pp, "
                  f"{100 * (tot_g - tot_p) / tot_g:+.1f}% of the guard's total")
        print()
        print("  Read this together with what it costs to get:")
        print("  in-process mode needs the target's MCP server source patched, needs the")
        print("  caller's scope supplied as configuration, and stops working entirely on")
        print("  an agent whose internals we cannot reach. **If the difference is small,")
        print("  the general design is cheap and this overlay is not worth its price.**")
    else:
        print("  one mode run; pass --mode both for the comparison")
    print("=" * 100)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
