"""Corpus-seed holdout: does the detector depend on the SEED it was developed against?

The question, stated precisely
------------------------------
`generate(seed=1337, total=5200, malicious_target=80)` produced every corpus this
project has measured on, and the detector was iterated against it 42 times. A different
seed changes which prompts are drawn, which accounts appear, which tickets and repos are
named, and where the malicious slots fall.

**What this DOES test**: whether any rule keys on corpus-specific TEXT -- a ticket id, a
hostname, a prompt phrasing that happens to appear at seed 1337. A detector that carries
such a dependency passes on its own seed and fails on the next one, and that is exactly
the class of overfitting a held-out seed exposes.

**What this does NOT test**: behaviour. `benign_variants` and the attack templates are
fixed lists, so a new seed re-rolls the WORDS over the same six benign shapes and the
same seven attack shapes. The report says so; this file must not be read as a
generalisation result.

    python track2/eval/seed_holdout.py
"""
from __future__ import annotations

import collections
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
RANGE = REPO / "_scratch" / "competition" / "agentrange"
sys.path.insert(0, str(REPO / "track2" / "detector"))
sys.path.insert(0, str(RANGE / "corpus-generator"))

from rules import (ALERT, BLOCK, analyse_session, clear_cross_session_state,  # noqa: E402
                   learn_resource_universe, remember_session)
from session import Session, ToolCall, load_tool_meta  # noqa: E402

COUNTED = (BLOCK, ALERT)
INV = RANGE / "evidence" / "inventory.json"

#: Seed 1337 is the one every other experiment used. 20261003 is the date this was
#: written; 7 and 424242 exist to show the result is not a property of one number.
SEEDS = [1337, 20261003, 7, 424242]


#: The generator writes tool names underscore-joined (`gitlab_get_pr`), while the
#: detector addresses tools as `<server>.<tool>`. The split point is ambiguous from the
#: string alone -- `shell_runner_run` could divide several ways -- so it is resolved
#: against the known server list by longest prefix, and anything that does not match is
#: skipped rather than guessed at. A wrong split would invent a held-out failure.
SERVERS = ["customer-db", "sandbox-exec", "shell-runner", "threat-intel", "notes-sync",
           "monitoring", "knowledge", "gitlab"]


def _split_tool(name: str) -> Optional[tuple]:
    for srv in sorted(SERVERS, key=len, reverse=True):
        prefix = srv.replace("-", "_") + "_"
        if name.startswith(prefix):
            return srv, name[len(prefix):]
    return None


def build(events: List[Any]) -> List[Session]:
    """Turn generated events into sessions the way the pipeline does.

    Reads the generator's own records, so a new seed can be judged without a replay --
    a replay per seed would need the range up and would take minutes each.
    """
    out: List[Session] = []
    skipped = 0
    for e in events:
        s = Session(instance_id=e.instance_id)
        actor = getattr(e, "actor", None)
        s.identity = actor if isinstance(actor, dict) else {}
        inp = getattr(e, "input", None) or {}
        s.prompt = inp.get("prompt") or ""
        s.skill = inp.get("skill") or ""
        for step in getattr(e, "trajectory", []) or []:
            if not isinstance(step, dict):
                continue
            for tc in step.get("tool_calls") or []:
                fn = (tc.get("function") or {}) if isinstance(tc, dict) else {}
                raw = fn.get("name") or ""
                pair = _split_tool(raw)
                if pair is None:
                    skipped += 1
                    continue
                server, tool = pair
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except Exception:  # noqa: BLE001
                    args = {}
                s.calls.append(ToolCall(server=server, tool=tool,
                                        arguments=args if isinstance(args, dict) else {}))
        if s.calls or s.prompt:
            out.append(s)
    if skipped:
        print(f"    (skipped {skipped} tool calls whose server could not be resolved)")
    return out


def judge(sessions: List[Session]) -> Dict[str, Set[str]]:
    clear_cross_session_state()
    learn_resource_universe(sessions)
    out: Dict[str, Set[str]] = {}
    for s in sessions:
        out[s.instance_id] = {f.rule_id for f in analyse_session(s)
                              if f.severity in COUNTED}
        remember_session(s)
    return out


def main() -> int:
    import generate
    if INV.exists():
        load_tool_meta(INV)

    print("=" * 100)
    print("CORPUS-SEED HOLDOUT -- does the detector depend on seed 1337?")
    print("=" * 100)
    print("  Seed 1337 is the one every measurement in this project used, and the")
    print("  detector was iterated against it 42 times. A different seed re-rolls the")
    print("  text without changing the shapes (see the module docstring).")
    print()

    rows = []
    for seed in SEEDS:
        events = generate.generate(seed=seed, total=5200, malicious_target=80)
        gt = {e.instance_id: bool(e.malicious) for e in events}
        sessions = build(events)
        verdicts = judge(sessions)

        tp = fp = fn = tn = 0
        rules: collections.Counter = collections.Counter()
        for sid, found in verdicts.items():
            mal = gt.get(sid, False)
            if mal and found:
                tp += 1
                rules.update(found)
            elif mal:
                fn += 1
            elif found:
                fp += 1
                rules.update({f"FP:{r}" for r in found})
            else:
                tn += 1
        rows.append((seed, len(sessions), tp, fp, fn, tn, rules))
        rec = 100 * tp / max(tp + fn, 1)
        prec = 100 * tp / max(tp + fp, 1)
        print(f"  seed {seed:<10} sessions {len(sessions):<5} "
              f"TP={tp:<4} FP={fp:<4} FN={fn:<4} TN={tn:<5} "
              f"recall={rec:5.1f}%  precision={prec:6.1f}%")

    print()
    print("-" * 100)
    base = rows[0][2] / max(rows[0][2] + rows[0][4], 1)
    worst = min(r[2] / max(r[2] + r[4], 1) for r in rows[1:])
    worst_fp = max(r[3] for r in rows)
    print(f"  seed 1337 recall {100 * base:.1f}%   worst held-out seed recall "
          f"{100 * worst:.1f}%   max false positives on any seed {worst_fp}")
    if worst >= base - 0.001:
        print()
        print("  No degradation across seeds: no rule depends on text that only exists")
        print("  at seed 1337. This rules out one specific failure mode -- a rule keyed")
        print("  to a ticket id, a hostname or a phrasing -- and nothing else.")
    else:
        print()
        print("  Recall drops on a held-out seed. Something in the rules is reading")
        print("  corpus text rather than structure, and the rules that lose the most")
        print("  are listed below.")
    print()
    print("  NOT tested here: behaviour. The benign variants and the attack templates")
    print("  are fixed lists, so every seed produces the same six benign shapes and the")
    print("  same seven attack shapes in different words. **A clean sheet here is not a")
    print("  generalisation result** and must not be quoted as one.")
    print("=" * 100)
    return 0 if worst >= .95 and worst_fp == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
