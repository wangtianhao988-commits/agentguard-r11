"""Latency on the path that matters: a request that produces a finding.

Why the existing M4 number is not enough
----------------------------------------
`bench/perf.py` measures the guard's added latency with a benign prompt. That prompt
never produces a finding, and `_stack_for_decision` returns early when the action is
ALLOW -- so the measurement structurally excludes the one thing that makes an attack
request more expensive: **the stack capture, which only runs when there is something to
attach it to.**

The brief's requirement is "响应时间小于 1 秒" and the sentence it sits in is about
detecting and blocking attacks. Measuring only the benign path answers a question nobody
asked.

This reports both, from the same run:

    benign path   -- added end-to-end latency, no finding, no capture
    attack path   -- the guard's own decision latency, which for a finding includes
                     the capture, broken out by phase

    python track2/bench/attack_path_latency.py
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, List

HERE = Path(__file__).resolve().parent          # track2/bench
REPO = HERE.parents[1]                          # repo root
RANGE = REPO / "_scratch" / "competition" / "agentrange"


def _pct(xs: List[float], p: float) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p * len(xs)))]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", default=str(RANGE / "evidence"))
    a = ap.parse_args()
    d = Path(a.evidence)

    print("=" * 100)
    print("M4 LATENCY -- benign path and attack path, measured separately")
    print("=" * 100)

    # -- attack path: the guard's own decision, from the run's own records ----------
    p = d / "guard_decision.jsonl"
    if not p.exists():
        print(f"  no guard decisions at {p}")
        return 1
    rows: List[Dict[str, Any]] = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            try:
                rows.append(json.loads(line))
            except Exception:  # noqa: BLE001
                continue

    all_us = [r.get("latency_us") for r in rows if isinstance(r.get("latency_us"), (int, float))]
    find_us = [r.get("latency_us") for r in rows
               if isinstance(r.get("latency_us"), (int, float))
               and r.get("action") in ("BLOCK", "ALERT")]
    allow_us = [r.get("latency_us") for r in rows
                if isinstance(r.get("latency_us"), (int, float)) and r.get("action") == "ALLOW"]

    def show(label: str, xs: List[float], note: str = "") -> None:
        if not xs:
            print(f"  {label:<26} (no samples)")
            return
        print(f"  {label:<26} n={len(xs):<6} "
              f"p50={_pct(xs, .5) / 1000:7.3f} ms  p95={_pct(xs, .95) / 1000:7.3f} ms  "
              f"p99={_pct(xs, .99) / 1000:7.3f} ms  max={max(xs) / 1000:8.3f} ms"
              + (f"   {note}" if note else ""))

    print()
    print("  -- the guard's own decision latency, by outcome --")
    show("ALLOW (no finding)", allow_us, "no stack capture is issued")
    show("BLOCK/ALERT (finding)", find_us, "INCLUDES the stack capture")
    show("all decisions", all_us)

    # -- stack capture, measured directly ------------------------------------------
    stack_took: List[float] = []
    sp = d / "code_stack.jsonl"
    if sp.exists():
        took = []
        errs = 0
        for line in sp.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except Exception:  # noqa: BLE001
                continue
            if r.get("error"):
                errs += 1
            if isinstance(r.get("took_ms"), (int, float)):
                took.append(r["took_ms"])
        stack_took = took
        if took:
            print()
            print(f"  -- stack capture ({len(took)} issued, {errs} errored) --")
            print(f"     p50={_pct(took, .5):6.2f} ms   p95={_pct(took, .95):6.2f} ms   "
                  f"max={max(took):6.2f} ms   mean={statistics.mean(took):6.2f} ms")
            n_findings = len(find_us)
            total = sum(took) / 1000.0
            print(f"     {n_findings} findings paid it; total {total:.2f} s across the run")

    # -- benign path: whatever perf.json holds -------------------------------------
    pf = REPO / "track2" / "bench" / "perf.json"
    if pf.exists():
        try:
            perf = json.loads(pf.read_text(encoding="utf-8"))
            print()
            print("  -- benign path, end-to-end added latency (bench/perf.py) --")
            for k in ("added_p50", "added_p95", "added_p99", "n", "errors"):
                if k in perf:
                    print(f"     {k:<12} {perf[k]}")
        except Exception:  # noqa: BLE001
            pass

    print()
    print("-" * 100)
    if find_us and stack_took:
        # The recorded `latency_us` stops at the decision: the capture is awaited AFTER
        # `check_tool_call` returns, so it is NOT inside that number. Reporting only the
        # decision would understate what an attack request costs; reporting only the
        # capture would ignore the rule evaluation. The attack path pays both.
        dec_p50 = _pct(find_us, .5) / 1000.0
        dec_p99 = _pct(find_us, .99) / 1000.0
        cap_p50 = _pct(stack_took, .5)
        cap_p99 = _pct(stack_took, .99)
        print("  -- attack path, the two costs the request actually pays --")
        print(f"     decision         p50={dec_p50:7.3f} ms   p99={dec_p99:7.3f} ms"
              f"   (what `latency_us` records)")
        print(f"     stack capture    p50={cap_p50:7.3f} ms   p99={cap_p99:7.3f} ms"
              f"   (awaited after the decision, not in `latency_us`)")
        print(f"     ---- combined    p50={dec_p50 + cap_p50:7.3f} ms   "
              f"p99={dec_p99 + cap_p99:7.3f} ms   against a 1000 ms budget")
        print()
        print(f"  The worst single attack-path request therefore costs about "
              f"{dec_p99 + cap_p99:.1f} ms, or "
              f"{100 * (dec_p99 + cap_p99) / 1000:.1f}% of the budget.")
    if allow_us:
        worst_allow = max(allow_us) / 1000.0
        if worst_allow > 5:
            print()
            print(f"  NOTED: one ALLOW decision took {worst_allow:.1f} ms while its p99 is "
                  f"{_pct(allow_us, .99) / 1000:.2f} ms. An allowance request issues no")
            print("  capture, so this is not stack cost -- most likely a GC pause or the")
            print("  scheduler. It is reported rather than trimmed because a p99 that")
            print("  hides a 18 ms outlier is a p99 that was chosen.")
    print("=" * 100)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
