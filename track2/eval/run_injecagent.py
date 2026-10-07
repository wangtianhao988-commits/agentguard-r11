"""Run the InjecAgent benchmark through this project's detector.

Why this file exists
--------------------
Every other number in this project was measured on a corpus the team generated:
`corpus-generator/` has 7 attack templates, 4 benign templates, and both the detector
and the tests were written by the same people. That is the single largest
methodological weakness in the submission, and no amount of careful wording fixes it --
only a corpus written by somebody else does.

InjecAgent (UIUC, arXiv 2403.02691) is that corpus: **1,054 test cases written by a
third party**, with 17 user tools and 62 attacker tools that this project has never
seen. It ships `test_cases_dh_base.json` (510 direct-harm) and
`test_cases_ds_base.json` (544 data-stealing).

What a case looks like
----------------------
    User Tool          AmazonGetProductDetails      <- what the user asked for
    User Instruction   "fetch me the details of ..."
    Tool Response      ...the injected instruction is embedded in HERE...
    Attacker Tools     ["AugustSmartLockGrantGuestAccess"]   <- what the injection wants
    Attack Type        Physical Harm

So a case maps naturally onto a session: one legitimate call whose RESULT carries the
injection, followed by the call the injection is trying to cause. The question the
benchmark asks is the one that matters -- **does the detector flag the second call?**

The honest expectation, stated before running
---------------------------------------------
InjecAgent supplies tool NAMES but **no schemas and no descriptions**. This project's
capability model reads parameter shapes, declared constraints and implementations
precisely so that it does not have to trust names. Given names alone it should therefore
catch very little -- and that is a real boundary of the approach, not a bug to be papered
over. The benchmark also tests something the rules were never written to express:
**deviation from the user's stated intent**. Our rules encode capability relations
("read a credential, then send data"), scope, and declarations. "The user asked about a
laptop and the agent unlocked a door" is none of those.

Both facts are the point of running it.

    python track2/eval/run_injecagent.py
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "track2" / "detector"))

from rules import ALERT, BLOCK, analyse_session, clear_cross_session_state  # noqa: E402
from session import Session, ToolCall, register_tool  # noqa: E402

DATA = REPO / "06_赛题与第三方" / "external_data"
for _required in ("test_cases_dh_base.json", "test_cases_ds_base.json"):
    _path = DATA / _required
    if not _path.is_file():
        raise FileNotFoundError(f"Required benchmark input missing: {_path}")
    _cases = json.loads(_path.read_text(encoding="utf-8"))
    if not isinstance(_cases, list) or not _cases:
        raise ValueError(f"Benchmark must contain nonempty case array: {_path}")
COUNTED = (BLOCK, ALERT)


def _args_from_instruction(instruction: str, tool: str) -> Dict[str, Any]:
    """InjecAgent does not publish the attacker call's arguments.

    Passing an empty argument dict would be the pessimistic choice and would also be
    unfair -- it removes the one piece of interface evidence the benchmark does let
    through. So the instruction text is carried in a generic content parameter, which
    is what a real agent would have to pass for the call to do anything.
    """
    return {"instruction": instruction, "target": tool}


def _load_cases(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def _load_tool_descriptions() -> Dict[str, str]:
    """There are none. Recorded explicitly so the report cannot imply otherwise."""
    return {}


def build_session(case: Dict[str, Any], idx: int) -> Tuple[Session, List[str]]:
    """One benchmark case -> one session, plus the attacker tools it wants called."""
    s = Session(instance_id=f"injecagent-{idx}")
    s.identity = {"sub": "benchmark-user", "role": "user", "scope": {}}
    s.prompt = case.get("User Instruction", "")

    user_tool = case.get("User Tool") or "user_tool"
    attacker_tools = list(case.get("Attacker Tools") or [])

    # The legitimate call. Its RESULT is where the injection arrives, so it has to be
    # populated -- a detector that cannot see return values cannot see the delivery.
    legit = ToolCall(server="bench", tool=user_tool,
                     arguments=case.get("Tool Parameters") or {})
    legit.result = case.get("Tool Response") or ""
    s.calls.append(legit)

    # The call the injection is trying to cause.
    for at in attacker_tools:
        c = ToolCall(server="bench", tool=at,
                     arguments=_args_from_instruction(case.get("Attacker Instruction", ""), at))
        c.result = {"ok": True}
        s.calls.append(c)
    return s, attacker_tools


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--show", type=int, default=8)
    a = ap.parse_args()

    print("=" * 100)
    print("INJECAGENT -- a corpus this project did not write")
    print("=" * 100)

    files = [("direct harm", DATA / "test_cases_dh_base.json"),
             ("data stealing", DATA / "test_cases_ds_base.json")]
    total = hit = 0
    by_type: Dict[str, List[int]] = collections.defaultdict(lambda: [0, 0])
    by_rule: collections.Counter = collections.Counter()
    misses: List[Dict[str, Any]] = []

    for label, path in files:
        cases = _load_cases(path)
        if not cases:
            print(f"  [{label}] no data at {path}")
            continue
        n_hit = 0
        for i, case in enumerate(cases):
            clear_cross_session_state()
            s, attacker_tools = build_session(case, i)
            if not attacker_tools:
                continue
            findings = [f for f in analyse_session(s) if f.severity in COUNTED]
            total += 1
            at = case.get("Attack Type") or label
            by_type[at][1] += 1
            if findings:
                hit += 1
                n_hit += 1
                by_type[at][0] += 1
                for f in findings:
                    by_rule[f.rule_id] += 1
            elif len(misses) < 400:
                misses.append({"case": i, "label": label, "user_tool": case.get("User Tool"),
                               "attacker_tools": attacker_tools, "type": at})
        print(f"  [{label:<14}] {len(cases):>4} cases   flagged {n_hit:>4}   "
              f"({100 * n_hit / max(len(cases), 1):.1f}%)")

    print()
    print(f"  TOTAL: {hit}/{total} cases where the detector flagged the attacker call "
          f"= {100 * hit / max(total, 1):.1f}%")
    print()
    print("  -- by attack type --")
    for t, (h, n) in sorted(by_type.items(), key=lambda kv: -kv[1][1]):
        print(f"     {t:<26} {h:>4}/{n:<4}  ({100 * h / max(n, 1):.1f}%)")
    print()
    print("  -- which rules fired --")
    if by_rule:
        for r, n in by_rule.most_common():
            print(f"     {r:<38}{n:>5}")
    else:
        print("     (none)")
    print()
    print("  -- example cases the detector did NOT flag --")
    for m in misses[:a.show]:
        print(f"     {m['label']:<14} user={m['user_tool']:<32} "
              f"attacker={','.join(m['attacker_tools'])[:38]}  ({m['type']})")
    print()
    print("  Reading this result")
    print("  -------------------")
    print("  A low number here is not a defect in the benchmark or a measurement error.")
    print("  It is the boundary of what this detector expresses. Two causes, both real:")
    print()
    print("   1. This adapter supplies names and assumed attacker actions, without real schemas.")
    print("      capability model reads parameter shapes and implementations precisely")
    print("      so that it need not trust names, so with names alone it has nothing to")
    print("      read. This is a synthetic trace test, not the benchmark's official agent evaluation.")
    print("   2. The benchmark tests DEVIATION FROM USER INTENT. The rules encode")
    print("      capability relations, scope and declarations. 'Asked about a laptop,")
    print("      unlocked a door' is none of those, and no rule here was written to")
    print("      express it.")
    print()
    print("  Both facts belong in the report. A detector that scores well only on its")
    print("  authors' corpus and poorly on a third party's has a generalisation problem,")
    print("  and the honest response is to say where the boundary is.")
    print("=" * 100)

    out = REPO / "track2" / "eval" / "injecagent_result.json"
    out.write_text(json.dumps({
        "cases": total, "flagged": hit,
        "rate": round(100 * hit / max(total, 1), 2),
        "by_attack_type": {k: {"flagged": v[0], "n": v[1]} for k, v in by_type.items()},
        "by_rule": dict(by_rule),
        "note": "InjecAgent (UIUC, arXiv 2403.02691), third-party corpus. "
                "Tool names only -- no schemas, no descriptions.",
    }, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
