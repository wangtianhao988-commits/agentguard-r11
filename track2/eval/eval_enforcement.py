#!/usr/bin/env python
"""Score the ENFORCEMENT layer: what got blocked, and what got blocked by mistake.

Why this is separate from `evaluate.py`
---------------------------------------
`evaluate.py` scores the detector offline: given evidence, did it produce a finding.
This scores the guard inline: given a live request, did it refuse the right one and
leave the business alone. The brief makes both explicit and they fail differently.

    "阻断机制应保证正常业务可用性"   -- 业务 0 中断

The binding number here is not recall. It is **how many benign sessions were refused**.
A guard that blocks everything scores 100% on detection and is worthless; a guard that
blocks nothing is safe and useless. Both are reported, and the false-block count is the
one that decides whether the mechanism can be switched on.

    python track2/eval/eval_enforcement.py --evidence <dir>
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
RANGE = REPO / "_scratch" / "competition" / "agentrange"
sys.path.insert(0, str(RANGE / "corpus-generator"))


def load_decisions(d: Path) -> List[Dict[str, Any]]:
    p = d / "guard_decision.jsonl"
    out: List[Dict[str, Any]] = []
    if not p.exists():
        return out
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed decision evidence in {p}: {exc}") from exc
    return out


def ground_truth() -> Dict[str, bool]:
    import generate  # type: ignore
    return {e.instance_id: bool(e.malicious) for e in generate.generate()}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", default=str(RANGE / "evidence"))
    ap.add_argument("--json", default=None)
    a = ap.parse_args()

    d = Path(a.evidence)
    decisions = load_decisions(d)
    gt = ground_truth()
    if any(x.get("action") not in {"ALLOW", "ALERT", "BLOCK"} for x in decisions):
        raise ValueError("Invalid or missing action in decision evidence")
    if any(x.get("action") not in {"ALLOW", "ALERT", "BLOCK"} for x in decisions):
        raise ValueError("Invalid or missing action in decision evidence")

    print("=" * 100)
    print("ENFORCEMENT SCORING -- what the guard refused, and what it refused wrongly")
    print("=" * 100)
    print(f"  decision records : {len(decisions)}")

    if not decisions:
        print("\n  no guard decisions found. Enforcement may be off, or the run predates it.")
        print("  Check `GET /debug/guard` on the gateway.")
        return 1

    blocked = [x for x in decisions if x.get("action") == "BLOCK"]
    alerted = [x for x in decisions if x.get("action") == "ALERT"]
    allowed = [x for x in decisions if x.get("action") == "ALLOW"]

    # A decision is attributed to a session via the trace id the guard carries.
    def sid(x: Dict[str, Any]) -> str:
        s = x.get("session_id") or ""
        return s.split(" ", 1)[0]

    blocked_sessions: Set[str] = {sid(x) for x in blocked}
    alerted_sessions: Set[str] = {sid(x) for x in alerted}

    mal_sessions = {k for k, v in gt.items() if v}
    ben_sessions = {k for k, v in gt.items() if not v}

    # Only sessions the guard actually saw can be judged. A category-1 session never
    # reaches the agent, so its absence is not a miss by this layer.
    seen = blocked_sessions | alerted_sessions | {sid(x) for x in allowed}
    seen_mal = seen & mal_sessions
    seen_ben = seen & ben_sessions

    tp = len(blocked_sessions & mal_sessions)       # malicious session refused
    fp = len(blocked_sessions & ben_sessions)       # BENIGN session refused = business break
    alert_mal = len((alerted_sessions - blocked_sessions) & mal_sessions)
    alert_ben = len((alerted_sessions - blocked_sessions) & ben_sessions)

    print()
    print("  -- 业务 0 中断 (the binding constraint) --")
    print(f"     benign sessions the guard saw      : {len(seen_ben)}")
    print(f"     benign sessions it REFUSED         : {fp}"
          f"   {'PASS' if fp == 0 else 'FAIL -- business was interrupted'}")
    print(f"     benign sessions it raised an alert on: {alert_ben}")
    print()
    print("  -- detection --")
    print(f"     malicious sessions the guard saw   : {len(seen_mal)}")
    print(f"     malicious sessions it REFUSED      : {tp}"
          f"   ({tp / len(seen_mal):.1%} of those seen)" if seen_mal else "")
    print(f"     malicious sessions alerted only    : {alert_mal}")
    print()

    lat = [x.get("latency_us") for x in decisions if isinstance(x.get("latency_us"), (int, float))]
    if lat:
        lat.sort()
        q = lambda p: lat[min(len(lat) - 1, int(p * len(lat)))]
        print("  -- decision latency (guard's own work, not the proxied request) --")
        print(f"     p50={q(.5):.0f}us  p95={q(.95):.0f}us  p99={q(.99):.0f}us  max={lat[-1]:.0f}us")
        print(f"     budget is 1 s for the whole response; the guard's share is "
              f"{q(.99) / 1e3:.3f} ms at p99")
    print()

    print("  -- which rules refused --")
    cnt = collections.Counter()
    for x in blocked:
        for f in x.get("findings") or []:
            if f.get("severity") == "BLOCK":
                cnt[f.get("rule_id")] += 1
    for r, n in cnt.most_common():
        print(f"     {r:<38}{n:>5}")

    if fp:
        print()
        print("  -- BENIGN SESSIONS REFUSED (must be empty) --")
        for s in sorted(blocked_sessions & ben_sessions)[:20]:
            why = next((x for x in blocked if sid(x) == s), {})
            print(f"     {s:<28}{why.get('server')}.{why.get('tool')}")
            print(f"        {str(why.get('reason'))[:120]}")

    print()
    print("  Reading: recall is the easy half. The number that decides whether this can")
    print("  be switched on in production is the benign-refusal count, because that is")
    print("  the one that costs a business transaction.")
    print("=" * 100)

    if a.json:
        Path(a.json).write_text(json.dumps({
            "decisions": len(decisions),
            "blocked": len(blocked), "alerted": len(alerted), "allowed": len(allowed),
            "benign_sessions_seen": len(seen_ben), "benign_refused": fp,
            "malicious_sessions_seen": len(seen_mal), "malicious_refused": tp,
            "malicious_pre_send_refused":len({sid(x) for x in blocked if x.get('point')=='mcp'}&mal_sessions),
            "malicious_result_intervened":len({sid(x) for x in blocked if x.get('point')=='result'}&mal_sessions),
            "result_projections":sum(x.get('intervention_action')=='PROJECT' for x in blocked),
            "result_refusals":sum(x.get('intervention_action')=='DENY_RESULT' for x in blocked),
            "malicious_alerted_only": alert_mal, "benign_alerted": alert_ben,
            "latency_us": {"p50": lat[len(lat) // 2] if lat else None,
                           "p99": lat[int(0.99 * len(lat))] if lat else None},
        }, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"wrote {a.json}")
    expected = {e.instance_id for e in __import__("generate").generate()
                if not e.scenario.startswith("C1")}
    missing = expected - seen
    errors = [x for x in decisions if "guard error" in str(x.get("reason", ""))]
    if missing or errors:
        print(f"INVALID measurement: missing sessions={len(missing)}, guard errors={len(errors)}")
        return 2
    expected = {e.instance_id for e in __import__("generate").generate()
                if not e.scenario.startswith("C1")}
    missing = expected - seen
    errors = [x for x in decisions if "guard error" in str(x.get("reason", ""))]
    if missing or errors:
        print(f"INVALID measurement: missing sessions={len(missing)}, guard errors={len(errors)}")
        return 2
    return 0 if fp == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
