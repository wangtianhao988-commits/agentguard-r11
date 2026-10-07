#!/usr/bin/env python
"""Evaluate the detector against the corpus ground truth.

Where the labels come from, and why that is legitimate
------------------------------------------------------
`corpus-generator/generate.py:34-39` strips `malicious` and `kind` from the public
record, and the corpus only ever exists in the runner's memory. A *detector* must not
have them -- reading them would be the same cheat as using the forbidden
`/admin/trajectories` endpoint.

An *evaluator* must have them, or there is nothing to evaluate against. So this script
re-derives the labels by calling the generator with the same seed the runner uses
(`generate(seed=1337, total=5200, malicious_target=80)`) and joins on `instance_id`.
The detector itself never imports this module.

Reading the metrics honestly
---------------------------
* **Recall is reported per scenario as well as pooled.** Every scenario has only 11-12
  positives, so ONE miss is 8.3-9.1% and breaches the brief's 5% miss bar for that
  scenario. A pooled 95% can hide a scenario that is completely undetected, so both
  views are printed and the per-scenario one is the binding one.
* **False-positive rate is reported both ways.** Per-event (<5% of 5120 benign = up to
  256) is the generous reading; per-alert precision (>=95%, i.e. at most ~4 false
  positives for 80 true ones) is the strict reading. At a 65:1 imbalance these differ
  by two orders of magnitude, and quoting only the flattering one would be dishonest.
* **INFO findings are excluded from every count.** An audit trail that inflates the
  detection rate is not a measurement.

    python track2/eval/evaluate.py --evidence <dir>
    python track2/eval/evaluate.py --evidence <dir> --json out.json
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "track2" / "detector"))

from rules import (ALERT, BLOCK, INFO, analyse_session, decide,  # noqa: E402
                   rule_framework_calls, analyse_stream)
from session import build_sessions, load_evidence  # noqa: E402

RANGE = REPO / "_scratch" / "competition" / "agentrange"
sys.path.insert(0, str(RANGE / "corpus-generator"))


def ground_truth() -> Dict[str, Dict[str, Any]]:
    import generate  # type: ignore
    out: Dict[str, Dict[str, Any]] = {}
    for e in generate.generate():
        out[e.instance_id] = {"malicious": bool(e.malicious), "scenario": e.scenario,
                              "kind": e.kind}
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", default=str(RANGE / "evidence"))
    ap.add_argument("--json", default=None)
    ap.add_argument("--show", type=int, default=12, help="how many findings to print")
    a = ap.parse_args()

    ev = load_evidence(a.evidence)
    sessions = build_sessions(ev)
    gt = ground_truth()

    # -- per-session findings -------------------------------------------
    per_session: Dict[str, List[Any]] = {}
    for s, findings in zip(sessions, analyse_stream(sessions)):
        if any(f.rule_id.endswith(":error") for f in findings):
            raise RuntimeError(f"Rule failure while evaluating {s.instance_id}")
        per_session[s.instance_id] = findings
    expected_agent = {iid for iid, label in gt.items()
                      if not label["scenario"].startswith("C1")}
    missing = expected_agent - set(per_session)
    if missing:
        raise ValueError(f"Incomplete corpus evidence: {len(missing)} agent sessions missing")

    # -- framework stream (observation E) --------------------------------
    fw_rows = []
    p = Path(a.evidence) / "E_framework_call.jsonl"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            if line.strip():
                fw_rows.append(json.loads(line))
    fw_findings = rule_framework_calls(fw_rows)

    flagged_sessions: Set[str] = {sid for sid, fs in per_session.items()
                                 if any(f.severity in (BLOCK, ALERT) for f in fs)}
    # Framework findings are counted against their own request stream. The two
    # streams have different denominators (a session vs an HTTP request), so they are
    # reported side by side rather than pooled into one figure that means neither.
    fw_flagged = len({f.session_id for f in fw_findings})

    # -- metrics: agent stream ------------------------------------------
    agent_ids = [i for i in gt if i in per_session]
    tp = fp = fn = tn = 0
    per_scen: Dict[str, List[int]] = collections.defaultdict(lambda: [0, 0])  # [hit, total]
    fp_ids: List[str] = []
    miss_ids: List[str] = []
    for iid in agent_ids:
        truth = gt[iid]["malicious"]
        pred = iid in flagged_sessions
        per_scen[gt[iid]["scenario"]][1] += 1
        if truth and pred:
            tp += 1
            per_scen[gt[iid]["scenario"]][0] += 1
        elif truth and not pred:
            fn += 1
            miss_ids.append(iid)
        elif not truth and pred:
            fp += 1
            fp_ids.append(iid)
        else:
            tn += 1

    recall = tp / (tp + fn) if (tp + fn) else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0

    # -- metrics: framework stream --------------------------------------
    # The 24 cat-1 events never reach the app, so they are absent from the session
    # stream entirely. They are evaluated on their own requests.
    fw_ids = {r.get("rid"): r for r in fw_rows}

    print("=" * 100)
    print("DETECTOR EVALUATION -- OpsPilot corpus")
    print("=" * 100)
    print(f"  evidence dir      : {a.evidence}")
    print(f"  sessions built    : {len(sessions)}")
    print(f"  ground-truth count: {len(gt)}   malicious={sum(1 for v in gt.values() if v['malicious'])}")
    print(f"  framework requests: {len(fw_rows)}   flagged: {fw_flagged}")
    print()

    print("  -- AGENT STREAM (observations A/B/C) --")
    print(f"     TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"     recall    = {recall:.1%}   (brief requires >= 95%)")
    print(f"     precision = {prec:.1%}   (brief requires >= 95%)")
    print(f"     FP rate over benign = {fp}/{tn + fp} = {fp / max(tn + fp, 1):.2%}  "
          f"(per-event reading; brief requires < 5%)")
    print()

    print("  -- PER SCENARIO (the binding constraint: n is 11-12) --")
    print(f"     {'scenario':<10}{'caught':>8}{'n':>5}{'miss rate':>12}{'ok?':>6}")
    for scen in sorted(per_scen):
        hit, n = per_scen[scen]
        if not gt_has_malicious(gt, scen):
            print(f"     {scen:<10}{'--':>8}{n:>5}{'':>12}{'(benign)':>6}")
            continue
        miss = 1 - hit / n if n else 1.0
        print(f"     {scen:<10}{hit:>8}{n:>5}{miss:>11.1%}{('ok' if miss < 0.05 else 'FAIL'):>6}")
    print()
    print(f"  per-scenario FAILURES (miss rate >= 5%): "
          f"{sum(1 for sc in per_scen if gt_has_malicious(gt, sc) and per_scen[sc][0] < per_scen[sc][1])}"
          f" / {sum(1 for sc in per_scen if gt_has_malicious(gt, sc))}")
    print()

    if fp_ids:
        print(f"  -- FALSE POSITIVES ({len(fp_ids)}) --")
        for iid in fp_ids[:a.show]:
            fs = [f for f in per_session[iid] if f.severity in (BLOCK, ALERT)]
            print(f"     {iid}  scenario={gt[iid]['scenario']}")
            for f in fs:
                print(f"        {f.severity:<6}{f.rule_id:<32}{f.summary[:80]}")
        print()

    if miss_ids:
        print(f"  -- MISSES ({len(miss_ids)}) --")
        by_scen = collections.Counter(gt[i]["scenario"] for i in miss_ids)
        print(f"     by scenario: {dict(by_scen)}")
        for iid in miss_ids[:a.show]:
            s = next((x for x in sessions if x.instance_id == iid), None)
            calls = [f"{c.server}.{c.tool}" for c in (s.calls if s else [])]
            print(f"     {iid}  scenario={gt[iid]['scenario']}  calls={calls}")
        print()

    print("  -- RULE FIRING COUNTS (agent stream) --")
    cnt = collections.Counter()
    sev = collections.defaultdict(collections.Counter)
    for fs in per_session.values():
        for f in fs:
            cnt[f.rule_id] += 1
            sev[f.rule_id][f.severity] += 1
    for rid, n in cnt.most_common():
        print(f"     {rid:<34}{n:>6}   {dict(sev[rid])}")
    print()
    print("  -- FRAMEWORK STREAM FINDINGS --")
    fcnt = collections.Counter(f.rule_id for f in fw_findings)
    print(f"     {dict(fcnt) if fcnt else '{}'}")
    print("=" * 100)

    if a.json:
        Path(a.json).write_text(json.dumps({
            "agent": {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "recall": recall,
                      "precision": prec, "fp_ids": fp_ids, "miss_ids": miss_ids,
                      "per_scenario": {k: {"hit": v[0], "n": v[1]} for k, v in per_scen.items()}},
            "framework": {"requests": len(fw_rows), "flagged": fw_flagged,
                          "rules": dict(fcnt)},
        }, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"wrote {a.json}")
    failures = any(1 - hit / n >= .05 for scen, (hit, n) in per_scen.items()
                   if gt_has_malicious(gt, scen) and n)
    return 1 if failures or recall < .95 or fp / max(tn + fp, 1) >= .05 else 0


def gt_has_malicious(gt: Dict[str, Dict[str, Any]], scen: str) -> bool:
    return any(v["malicious"] for v in gt.values() if v["scenario"] == scen)


if __name__ == "__main__":
    raise SystemExit(main())
