"""Does the verdict depend on the order the sessions arrive in?

Why this is asked
-----------------
The full replay drives the corpus as fast as the driver can, in a fixed order, once. Two
of the rules are stateful across sessions -- `cross-session-read-then-egress` and
`cross-session-memory-poisoning` both consult what a principal did earlier -- so the
detector's output is not obviously independent of ordering, and a single fixed-order run
cannot tell whether it is.

What is tested, and what is not
-------------------------------
The question worth asking is narrow: **does re-ordering create or remove findings on the
BENIGN side?** A false positive that appears only under some interleaving is the one that
would interrupt business in production, and it is invisible to a single run.

Order-dependence on the MALICIOUS side is expected and is not a defect: the cross-session
rules are defined in terms of "earlier", so shuffling malicious sessions legitimately
changes which one carries the finding. That is reported as information, not as a failure.

    python track2/eval/order_independence.py
"""
from __future__ import annotations

import argparse
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Set

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
RANGE = REPO / "_scratch" / "competition" / "agentrange"
sys.path.insert(0, str(REPO / "track2" / "detector"))
sys.path.insert(0, str(RANGE / "corpus-generator"))

from rules import (ALERT, BLOCK, analyse_session, clear_cross_session_state,  # noqa: E402
                   learn_resource_universe, remember_session)
from session import build_sessions, load_evidence  # noqa: E402

COUNTED = (BLOCK, ALERT)


def judge(sessions: List[Any]) -> Dict[str, Set[str]]:
    clear_cross_session_state()
    learn_resource_universe(sessions)
    out: Dict[str, Set[str]] = {}
    for s in sessions:
        out[s.instance_id] = {f.rule_id for f in analyse_session(s)
                              if f.severity in COUNTED}
        remember_session(s)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", default=str(RANGE / "evidence"))
    ap.add_argument("--shuffles", type=int, default=5)
    a = ap.parse_args()

    ev = load_evidence(Path(a.evidence))
    sessions = build_sessions(ev)
    import generate
    gt = {e.instance_id: bool(e.malicious) for e in generate.generate()}

    # A fresh build each time: `Session` accumulates cross-session markers.
    baseline = judge(build_sessions(ev))
    base_ben = {k for k, v in baseline.items() if v and k in gt and not gt[k]}

    print("=" * 100)
    print("ORDER INDEPENDENCE -- does re-arrival change the verdict?")
    print("=" * 100)
    print(f"  sessions {len(sessions)}   baseline benign findings {len(base_ben)}")
    print()

    rng = random.Random(20261003)
    bad = 0
    for trial in range(a.shuffles):
        shuffled = build_sessions(ev)
        rng.shuffle(shuffled)
        got = judge(shuffled)
        ben = {k for k, v in got.items() if v and k in gt and not gt[k]}
        mal_flagged = sum(1 for k, v in got.items() if v and gt.get(k))
        new = ben - base_ben
        lost = base_ben - ben
        status = "ok" if not new and not lost else "CHANGED"
        if new or lost:
            bad += 1
        print(f"  shuffle {trial + 1}: benign findings {len(ben):<4} "
              f"malicious flagged {mal_flagged:<4}  "
              f"new {len(new)}  lost {len(lost)}   {status}")
        for k in sorted(new)[:5]:
            print(f"      NEW on benign: {k} -> {sorted(got[k])}")
        for k in sorted(lost)[:5]:
            print(f"      LOST on benign: {k} -> {sorted(baseline[k])}")

    print()
    print("-" * 100)
    if bad == 0:
        print(f"  No benign finding appeared or disappeared across {a.shuffles} re-orderings.")
        print("  The cross-session state changes which session carries a finding, as it is")
        print("  defined to, but it does not manufacture one against benign traffic.")
    else:
        print(f"  {bad}/{a.shuffles} re-orderings changed the benign verdict.")
        print("  A false positive that depends on interleaving is the one that would")
        print("  interrupt production, and a single fixed-order run cannot see it.")
    print()
    print("  Scope: five re-orderings of one corpus, offline. This is not a test of")
    print("  concurrency -- the guard is single-threaded by construction -- and it does")
    print("  not exercise the live path. It answers only the ordering question.")
    print("=" * 100)
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
