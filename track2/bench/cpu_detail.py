#!/usr/bin/env python
"""Measure container CPU precisely, and settle which denominator is correct.

`docker stats` prints a single CPU% with no indication of its denominator, and the
two candidate readings differ by the core count here (32x). Reporting either without
saying which is how a number becomes unfalsifiable.

The engine API gives the raw counters, so both readings can be computed explicitly:

    cpu_delta    = cpu_stats.cpu_usage.total_usage  - precpu_stats.cpu_usage.total_usage
    system_delta = cpu_stats.system_cpu_usage       - precpu_stats.system_cpu_usage

    fraction_of_all_cores = cpu_delta / system_delta
    fraction_of_one_core  = fraction_of_all_cores * online_cpus

`docker stats` prints `fraction_of_all_cores * online_cpus * 100`, i.e. the same
number `top` would show -- percent of ONE core, where 100% = one saturated core and
a multi-threaded process can exceed 100%.

    python track2/bench/cpu_detail.py --container agentrange-guard-gateway --seconds 40
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
import urllib.request
from typing import Any, Dict, List, Optional

SOCK = "/var/run/docker.sock"


def _api(path: str, timeout: float = 10.0) -> Any:
    """Query the engine over the unix socket. urllib needs a custom handler."""
    import http.client
    import socket as _socket

    class UDSConnection(http.client.HTTPConnection):
        def __init__(self, uds: str, timeout: float = 10.0):
            super().__init__("localhost", timeout=timeout)
            self._uds = uds

        def connect(self):
            s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect(self._uds)
            self.sock = s

    c = UDSConnection(SOCK, timeout)
    c.request("GET", path)
    r = c.getresponse()
    return json.loads(r.read())


def cpu_sample(container: str) -> Optional[Dict[str, float]]:
    s = _api(f"/v1.44/containers/{container}/stats?stream=false")
    if not s:
        return None
    try:
        cd = (s["cpu_stats"]["cpu_usage"]["total_usage"]
              - s["precpu_stats"]["cpu_usage"]["total_usage"])
        sd = (s["cpu_stats"]["system_cpu_usage"]
              - s["precpu_stats"]["system_cpu_usage"])
        if sd <= 0:
            return None
        online = s["cpu_stats"].get("online_cpus") or 1
        frac_all = cd / sd
        return {"frac_of_all_cores": frac_all,
                "frac_of_one_core": frac_all * online,
                "online_cpus": online}
    except Exception:  # noqa: BLE001
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", default="agentrange-guard-gateway")
    ap.add_argument("--seconds", type=float, default=40.0)
    a = ap.parse_args()

    # The counters in a single `stream=false` call are deltas since the PREVIOUS
    # call, so the first one is meaningless. Prime it.
    cpu_sample(a.container)

    samples: List[Dict[str, float]] = []
    t_end = time.time() + a.seconds
    while time.time() < t_end:
        s = cpu_sample(a.container)
        if s:
            samples.append(s)
        time.sleep(1.0)

    if not samples:
        print("no samples")
        return 1

    online = int(samples[0]["online_cpus"])
    allc = [s["frac_of_all_cores"] * 100 for s in samples]
    onec = [s["frac_of_one_core"] * 100 for s in samples]

    print("=" * 96)
    print(f"CPU DETAIL -- {a.container}   ({len(samples)} samples over {a.seconds:.0f}s)")
    print("=" * 96)
    print(f"  online CPUs reported by the engine : {online}")
    print()
    print(f"  percent of ALL cores   mean={statistics.fmean(allc):6.2f}%  "
          f"p95={sorted(allc)[int(.95*len(allc))]:6.2f}%  max={max(allc):6.2f}%")
    print(f"  percent of ONE core    mean={statistics.fmean(onec):6.2f}%  "
          f"p95={sorted(onec)[int(.95*len(onec))]:6.2f}%  max={max(onec):6.2f}%")
    print()
    print("  `docker stats` prints the ONE-CORE figure (it multiplies by online_cpus),")
    print("  which is also what `top` shows. On this host the two differ by "
          f"{online}x.")
    print()
    print(f"  against the brief's '5%' budget:")
    print(f"    host-relative reading  : {'PASS' if statistics.fmean(allc) < 5 else 'FAIL'}"
          f"   ({statistics.fmean(allc):.2f}% of {online} cores)")
    print(f"    one-core reading       : {'PASS' if statistics.fmean(onec) < 5 else 'FAIL'}"
          f"   ({statistics.fmean(onec):.2f}% of one core)")
    print("=" * 96)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
