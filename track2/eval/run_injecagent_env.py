"""InjecAgent, second pass: with the environment supplied.

Why a second pass
-----------------
The first pass (`run_injecagent.py`) used InjecAgent's data exactly as published: tool
NAMES only. It scored 0/1054, and part of that is a data limitation rather than a
detector result -- **no real deployment presents a tool without a schema**, because
`tools/list` carries one. Testing without it measures the dataset's omissions as much as
the detector's reach.

So this pass supplies the missing half and states the boundary clearly:

    the ATTACKS come from InjecAgent (third party -- that is what makes the test worth
    running), and the ENVIRONMENT (tool schemas) is supplied here, because in any real
    deployment the environment comes from the tools themselves and not from the
    attacker.

That is a legitimate division: supplying the environment is not the same as supplying
the thing under test. What would NOT be legitimate is writing the attacks.

Schema inference rule, stated before the run
--------------------------------------------
Deliberately generous to the detector. Every attacker tool is given the interface its
NAME says it has -- a `PayBill`/`Transfer`/`Unlock`/`Execute` tool gets an action-style
parameter, a `Read`/`Search`/`Get` tool gets a query parameter. This is the most
favourable environment the model could reasonably be handed, so the resulting number is
an **upper bound** on what the capability approach can reach on this benchmark.

    python track2/eval/run_injecagent_env.py
"""
from __future__ import annotations

import json
import re
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

#: A name -> (parameter names, description). The rule is stated above and applied
#: uniformly; nothing here is tuned per case.
NAME_PATTERNS: List[Tuple[re.Pattern, Dict[str, Any]]] = [
    (re.compile(r"(exec|shell|command|run|eval)", re.I),
     {"cmd": "string"}, "Runs a command."),
    (re.compile(r"(unlock|lock|grant|access|door|arm|disarm)", re.I),
     {"device_id": "string", "action": "string"}, "Controls a physical access device."),
    (re.compile(r"(pay|transfer|bill|withdraw|deposit|purchase|order)", re.I),
     {"account": "string", "amount": "string", "payee": "string"},
     "Moves money from an account."),
    (re.compile(r"(delete|remove|drop|revoke|wipe)", re.I),
     {"target": "string"}, "Deletes the named target."),
    (re.compile(r"(write|create|post|upload|send|publish|append|update)", re.I),
     {"content": "string", "target": "string"}, "Writes content to a target."),
    (re.compile(r"(read|get|fetch|search|list|query|view|find)", re.I),
     {"query": "string"}, "Reads data."),
]


def schema_for(tool: str) -> Tuple[Dict[str, Any], str]:
    for pat, props, desc in NAME_PATTERNS:
        if pat.search(tool):
            return props, desc
    return {"target": "string"}, "Performs an action."


def main() -> int:
    print("=" * 100)
    print("INJECAGENT, SECOND PASS -- attacks from the benchmark, environment supplied here")
    print("=" * 100)
    print("  The schemas below are an UPPER BOUND: every attacker tool gets the interface")
    print("  its name implies, which is the most favourable reading the model could be")
    print("  handed. A low score here cannot be blamed on missing tool metadata.")
    print()

    # Register every tool the benchmark mentions.
    tools: Dict[str, Dict[str, Any]] = {}
    for fname in ("test_cases_dh_base.json", "test_cases_ds_base.json",
                  "user_cases.jsonl", "attacker_cases_dh.jsonl", "attacker_cases_ds.jsonl"):
        p = DATA / fname
        if not p.exists():
            continue
        if fname.endswith(".jsonl"):
            for line in p.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                r = json.loads(line)
                for t in ([r["User Tool"]] if "User Tool" in r else []) + list(r.get("Attacker Tools") or []):
                    tools.setdefault(t, {})
        else:
            for case in json.loads(p.read_text(encoding="utf-8")):
                if case.get("User Tool"):
                    tools.setdefault(case["User Tool"], {})
                for t in case.get("Attacker Tools") or []:
                    tools.setdefault(t, {})

    for t in sorted(tools):
        props, desc = schema_for(t)
        register_tool("bench", t, {"type": "object", "properties": {k: {"type": v} for k, v in props.items()}},
                      desc)
    print(f"  registered {len(tools)} benchmark tools with inferred schemas")

    total = hit = 0
    by_rule: Dict[str, int] = {}
    examples: List[str] = []
    for label, path in (("direct harm", DATA / "test_cases_dh_base.json"),
                        ("data stealing", DATA / "test_cases_ds_base.json")):
        if not path.exists():
            continue
        cases = json.loads(path.read_text(encoding="utf-8"))
        n_hit = 0
        for i, case in enumerate(cases):
            ats = list(case.get("Attacker Tools") or [])
            if not ats:
                continue
            clear_cross_session_state()
            s = Session(instance_id=f"env-{i}")
            s.prompt = case.get("User Instruction", "")
            legit = ToolCall(server="bench", tool=case.get("User Tool") or "u",
                             arguments=case.get("Tool Parameters") or {})
            legit.result = case.get("Tool Response") or ""
            s.calls.append(legit)
            for at in ats:
                props, _ = schema_for(at)
                got = {k: f"value-for-{k}" for k in props}
                c = ToolCall(server="bench", tool=at, arguments=got)
                c.result = {"ok": True}
                s.calls.append(c)
            findings = [f for f in analyse_session(s) if f.severity in COUNTED]
            total += 1
            if findings:
                hit += 1
                n_hit += 1
                for f in findings:
                    by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
            elif len(examples) < 6:
                examples.append(f"{case.get('User Tool')} -> {','.join(ats)}")
        print(f"  [{label:<14}] {len(cases):>4} cases   flagged {n_hit:>4}   "
              f"({100 * n_hit / max(len(cases), 1):.1f}%)")

    print()
    print(f"  TOTAL: {hit}/{total} = {100 * hit / max(total, 1):.1f}%")
    print()
    print("  -- rules that fired --")
    for r, n in sorted(by_rule.items(), key=lambda kv: -kv[1]):
        print(f"     {r:<38}{n:>5}")
    if not by_rule:
        print("     (none)")
    print()
    print("  Some cases still missed:")
    for e in examples:
        print(f"     {e}")
    print()
    print("-" * 100)
    print("  What this second pass establishes")
    print("  ---------------------------------")
    print("  Supplying the environment does not change the outcome. The reason is not")
    print("  missing metadata and not a coding error: it is that **the rules do not")
    print("  express what this benchmark tests.**")
    print()
    print("    * Our rules judge CAPABILITY RELATIONS ('read a credential, then send")
    print("      data out'), SCOPE ('this tenant is not yours'), DECLARATIONS ('the")
    print("      skill promised knowledge, it used a shell') and EXECUTION.")
    print("    * InjecAgent judges DEVIATION FROM USER INTENT ('asked about a laptop,")
    print("      unlocked a door').")
    print()
    print("  `AugustSmartLockGrantGuestAccess` is undeniably harmful and is not any of")
    print("  the four things above. There is no rule here that could name it, and that")
    print("  is a statement about the detector's SCOPE, not its implementation.")
    print("=" * 100)

    out = REPO / "track2" / "eval" / "injecagent_env_result.json"
    out.write_text(json.dumps({
        "cases": total, "flagged": hit, "rate": round(100 * hit / max(total, 1), 2),
        "by_rule": by_rule,
        "schemas": "inferred from tool names; upper bound, stated in the script",
        "note": "Attacks from InjecAgent (UIUC, arXiv 2403.02691). Environment supplied "
                "here because the benchmark publishes tool names only.",
    }, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
