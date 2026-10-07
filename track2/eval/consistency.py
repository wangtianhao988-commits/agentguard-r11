#!/usr/bin/env python
"""Do the offline evaluator and the live guard run the SAME detector?

Why this check exists
---------------------
They did not, and nothing noticed.

`cross-session-read-then-egress` was implemented, unit-tested against the adversarial
round, and reported as passing. It was also **dead in the live path**: `InlineGuard`
defined a `remember()` method and never called it, so the per-principal read history
stayed empty and the rule could not fire. The offline evaluator called
`remember_session` itself, so both paths reported 100% -- one of them while missing a
rule entirely.

Every number in the results report comes from one path or the other, and a claim like
"recall 100%" is only meaningful if the thing measured offline is the thing deployed.
So the two are now compared directly:

    offline  rules produced by `analyse_stream` over the evidence
    live     rules recorded by the guard in `guard_decision.jsonl`
    diff     per-session set difference, either direction

Any divergence is a defect in one of the two paths, or in the wiring between them.
There is no benign explanation, which is what makes it worth a permanent check.

    python track2/eval/consistency.py --evidence <dir>
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
sys.path.insert(0, str(REPO / "track2" / "detector"))

from rules import (ALERT, BLOCK, analyse_session, clear_cross_session_state,  # noqa: E402
                   learn_resource_universe, remember_session)
from session import build_sessions, load_evidence  # noqa: E402

COUNTED = (BLOCK, ALERT)

#: Stands for "this path produced no finding for this session". Both sides carry it, so
#: agreement on the silent majority is verified rather than assumed. See the note at the
#: live-path loop for why that matters.
NO_FINDING = "__no_finding__"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", default=str(RANGE / "evidence"))
    ap.add_argument("--show", type=int, default=10)
    a = ap.parse_args()

    d = Path(a.evidence)
    ev = load_evidence(d)
    sessions = build_sessions(ev)

    # -- offline path: same sequence the pipeline is supposed to use --------
    #
    # A session the offline path clears gets the same sentinel the live path uses, so
    # "both said nothing" is an agreement that was CHECKED rather than an absence that
    # was skipped. Without it the two sides agree only on the sessions that produced
    # findings, which is the minority.
    clear_cross_session_state()
    learn_resource_universe(sessions)
    offline: Dict[str, Set[str]] = {}
    for s in sessions:
        rules = {f.rule_id for f in analyse_session(s)
                 if getattr(f, "severity", "") in COUNTED}
        offline[s.instance_id] = rules or {NO_FINDING}
        remember_session(s)

    # -- live path: what the guard actually recorded ------------------------
    live: Dict[str, Set[str]] = collections.defaultdict(set)
    p = d / "guard_decision.jsonl"
    n_live = 0
    malformed = 0
    if p.exists():
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except Exception:  # noqa: BLE001
                continue
            n_live += 1
            sid = str(rec.get("session_id") or "")
            if rec.get("point") not in {"mcp","result"}:
                continue                      # framework path has no session id
            # **ALLOW decisions are recorded too, and that is the point of this change.**
            #
            # The first version kept only decisions carrying a BLOCK/ALERT finding, so
            # `live` was always the 56 malicious sessions and the comparison covered
            # about 1% of the corpus. The 5120 sessions that produced no finding were
            # never checked against the offline detector at all -- and that is exactly
            # where a rule that silently stopped firing would hide: it would look like a
            # quiet session, on both sides, which is the failure mode this file exists
            # to catch.
            # **Finding entries are tolerated in either shape; anything else is counted
            # rather than crashing the run.**
            #
            # An early in-process record wrote `findings` as a list of rule-id STRINGS
            # while the gateway writes a list of objects. `f.get("rule_id")` on a string
            # raised AttributeError and took the whole check down -- a reader whose job is
            # to detect divergence, stopped by one line it did not expect. Malformed
            # entries now count toward `malformed` and are skipped, and the check still
            # answers the question it exists to answer.
            rules: Set[str] = set()
            for f in rec.get("findings") or []:
                if isinstance(f, dict):
                    if f.get("severity") in COUNTED:
                        rules.add(str(f.get("rule_id")))
                elif isinstance(f, str):
                    rules.add(f)
                else:
                    malformed += 1
            if rules:
                live[sid] |= rules
            # **The sentinel is applied AFTER the whole session is read, not here.**
            #
            # Doing it inline was wrong: a session whose first call is clean and whose
            # third call trips a rule would collect the sentinel from the clean call and
            # the rule id from the third, and the comparison would then see
            # `{rule, NO_FINDING}` against the offline `{rule}` and report a divergence
            # that does not exist -- 34 of them, all C2-A, all artefacts of this line.
            # Whether a session is silent is a property of the session, not of one call.
            elif sid not in live:
                live[sid] = set()

    # Now that every decision has been read, a session that never produced a finding
    # gets the sentinel, and one that did keeps only its rules.
    for sid in list(live):
        if not live[sid]:
            live[sid] = {NO_FINDING}

    print("=" * 100)
    print("OFFLINE vs LIVE CONSISTENCY")
    print("=" * 100)
    print(f"  offline: {len(sessions)} sessions judged")
    print(f"  live   : {n_live} guard decisions over {len(live)} sessions")
    print()

    if n_live == 0:
        print("  no live decisions found -- the guard may be disabled, or evidence")
        print("  predates enforcement. Nothing to compare.")
        return 1

    missing_live = set(offline) - set(live)
    missing_offline = set(live) - set(offline)
    if malformed or missing_live or missing_offline:
        print(f"INVALID comparison: malformed={malformed}, "
              f"offline-only sessions={len(missing_live)}, live-only sessions={len(missing_offline)}")
        return 2

    only_offline: List[Any] = []
    only_live: List[Any] = []
    for sid in sorted(set(offline) & set(live)):
        o, l = offline[sid], live[sid]
        if o - l:
            only_offline.append((sid, sorted(o - l)))
        if l - o:
            only_live.append((sid, sorted(l - o)))

    print("  -- rules the OFFLINE path produced but the LIVE guard did not --")
    if only_offline:
        per_rule = collections.Counter(r for _, rs in only_offline for r in rs)
        for r, n in per_rule.most_common():
            print(f"     {r:<40}{n:>5} sessions")
        for sid, rs in only_offline[:a.show]:
            print(f"       e.g. {sid}: {rs}")
        if len(only_offline) > a.show:
            print(f"       ... and {len(only_offline) - a.show} more")
    else:
        print("     (none)")

    print()
    print("  -- rules the LIVE guard produced but the OFFLINE path did not --")
    if only_live:
        per_rule = collections.Counter(r for _, rs in only_live for r in rs)
        for r, n in per_rule.most_common():
            print(f"     {r:<40}{n:>5} sessions")
        for sid, rs in only_live[:a.show]:
            print(f"       e.g. {sid}: {rs}")
    else:
        print("     (none)")

    print()
    print("-" * 100)
    diverge = len(only_offline) + len(only_live)
    if diverge == 0:
        print("  CONSISTENT -- the deployed guard and the offline evaluator agree")
        print("  on every session they both saw.")
    else:
        print(f"  DIVERGENT -- {diverge} session(s) differ.")
        print()
        print("  This has no benign explanation. It means one of the two paths is")
        print("  missing a rule that the other has, so any metric quoted from either")
        print("  describes a detector that is not the one deployed. This exact check")
        print("  found `cross-session-read-then-egress` implemented, unit-tested, and")
        print("  never called by the live guard.")
    print("=" * 100)
    return 0 if diverge == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
