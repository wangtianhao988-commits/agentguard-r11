"""Hold out half of InjecAgent, and re-measure honestly.

The problem this addresses
--------------------------
The consequence vocabulary in `session.CONSEQUENCES` was written **after reading
InjecAgent's attacker tool names** -- `physical` exists because the benchmark has
`AugustSmartLockGrantGuestAccess`, `financial` because it has `BankManagerPayBill`. An
ablation showed that `financial` alone carries 53% of the improvement.

So 30.2% is a **training-set score**, exactly like the 100% it was meant to replace. The
project's central methodological failure had been reproduced one level up, on a better
corpus. A held-out measurement is the only thing that distinguishes a capability from a
fit.

The procedure, fixed before looking at any result
------------------------------------------------
1. **Split deterministically by hash of the tool name** -- not by hand, so no case can be
   moved between halves to flatter the score. Roughly half the attacker tools become the
   TUNING set and half the HOLDOUT set.
2. **Prune the vocabulary to what the tuning half independently justifies.** Every
   literal term in every consequence class is kept only if it appears in a TUNING tool
   name. A term that exists solely because of a holdout tool is removed. This is the
   mechanical stand-in for "design the rules without seeing the test set".
3. **Score on the holdout cases.** Cases whose attacker tool is in the tuning half are
   excluded from the headline number.

An honest limitation, stated up front
-------------------------------------
I have already read all 62 tool names, so step 2 is a *reconstruction* of what the
vocabulary would have been, not a genuine blind design. It removes terms that the tuning
set does not justify, which is the part that can be done mechanically; it cannot remove
what I remember. **The number below is therefore an upper bound on the true held-out
performance, and it is a much tighter bound than 30.2%.**

    python track2/eval/holdout_injecagent.py
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "track2" / "detector"))

import session as S  # noqa: E402
import rules as R  # noqa: E402

DATA = REPO / "06_赛题与第三方" / "external_data"
for _required in ("test_cases_dh_base.json", "test_cases_ds_base.json"):
    _path = DATA / _required
    if not _path.is_file():
        raise FileNotFoundError(f"Required benchmark input missing: {_path}")
    _cases = json.loads(_path.read_text(encoding="utf-8"))
    if not isinstance(_cases, list) or not _cases:
        raise ValueError(f"Benchmark must contain nonempty case array: {_path}")


def half(tool: str) -> str:
    """Deterministic 50/50 split. Hash, not judgement."""
    h = hashlib.sha256(tool.encode("utf-8")).hexdigest()
    return "tuning" if int(h[:8], 16) % 2 == 0 else "holdout"


def terms_of(pattern: "re.Pattern") -> List[str]:
    """The literal alternatives inside a compiled alternation."""
    src = pattern.pattern.strip("()")
    return [t for t in src.split("|") if t and not t.startswith("(?")]


def build_pruned_vocab(tuning_tools: Set[str]) -> Tuple[Dict[str, "re.Pattern"], List[str]]:
    """Keep only the vocabulary the TUNING half independently justifies."""
    pruned: Dict[str, "re.Pattern"] = {}
    dropped: List[str] = []
    hay = " ".join(tuning_tools)
    for klass, pat in S.CONSEQUENCES.items():
        kept = []
        for t in terms_of(pat):
            # `\b` and anchoring are regex machinery, not vocabulary; compare the词干
            core = t.replace("\\b", "").replace("\\", "")
            if re.search(re.escape(core), hay, re.I):
                kept.append(t)
            else:
                dropped.append(f"{klass}:{core}")
        if kept:
            pruned[klass] = re.compile("(" + "|".join(kept) + ")", re.I)
    return pruned, dropped


def collect_tools() -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {"tuning": set(), "holdout": set()}
    for f in DATA.glob("*.json*"):
        try:
            if f.suffix == ".jsonl":
                rows = [json.loads(l) for l in f.read_text(encoding="utf-8").splitlines() if l.strip()]
            else:
                rows = json.loads(f.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        for r in rows:
            for t in (r.get("Attacker Tools") or []):
                if t:
                    out[half(t)].add(t)
    return out


def score(cases_file: Path, vocab: Dict[str, "re.Pattern"],
          allowed: Set[str]) -> Tuple[int, int, Counter]:
    """Count holdout cases whose attacker tool the vocabulary would place in a
    high-consequence class. Uses the same contract-reading rule as production."""
    if not cases_file.exists():
        raise FileNotFoundError(cases_file)
    cases = json.loads(cases_file.read_text(encoding="utf-8"))
    hit = total = 0
    per_class: Counter = Counter()
    for c in cases:
        ats = [t for t in (c.get("Attacker Tools") or []) if t]
        if not ats:
            continue
        # only cases whose attacker tools were withheld count toward the headline
        if any(t in allowed for t in ats):
            continue
        total += 1
        for t in ats:
            normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", t)
            classes = {k for k, p in vocab.items() if p.search(normalized)}
            classes &= S.HIGH_CONSEQUENCE
            if classes:
                hit += 1
                per_class.update(classes)
                break
    return hit, total, per_class


def main() -> int:
    tools = collect_tools()
    print("=" * 100)
    print("INJECAGENT HOLDOUT -- splitting by tool hash, pruning by tuning half")
    print("=" * 100)
    print(f"  attacker tools: {len(tools['tuning'])} tuning / {len(tools['holdout'])} holdout")

    pruned, dropped = build_pruned_vocab(tools["tuning"])
    print()
    print("  -- vocabulary the TUNING half justifies --")
    for k in sorted(pruned):
        print(f"     {k:<12} {len(terms_of(pruned[k]))} terms")
    print()
    print(f"  -- dropped ({len(dropped)} terms the tuning half does NOT justify) --")
    for d in dropped[:30]:
        print(f"     {d}")
    if len(dropped) > 30:
        print(f"     ... and {len(dropped) - 30} more")

    if not tools["tuning"] or not tools["holdout"]:
        raise ValueError("Both split partitions must contain attacker tools")

    if not tools["tuning"] or not tools["holdout"]:
        raise ValueError("Both split partitions must contain attacker tools")

    # Install the pruned vocabulary for the measurement.
    saved = dict(S.CONSEQUENCES)
    S.CONSEQUENCES = pruned
    R.CONSEQUENCES = pruned

    print()
    print("  -- HOLDOUT scores (cases whose attacker tool was withheld) --")
    grand_h = grand_n = 0
    for label, f in (("direct harm", DATA / "test_cases_dh_base.json"),
                     ("data stealing", DATA / "test_cases_ds_base.json")):
        h, n, pc = score(f, pruned, tools["tuning"])
        grand_h += h
        grand_n += n
        rate = 100 * h / max(n, 1)
        print(f"     {label:<14} {h:>4}/{n:<4}  {rate:>5.1f}%")

    print()
    print(f"  >>> HOLDOUT TOTAL: {grand_h}/{grand_n} = {100 * grand_h / max(grand_n, 1):.1f}% <<<")

    if grand_n == 0:
        raise ValueError("No holdout cases were scored")

    if grand_n == 0:
        raise ValueError("No holdout cases were scored")

    # For contrast, the same split scored with the FULL (fitted) vocabulary.
    S.CONSEQUENCES = saved
    R.CONSEQUENCES = saved
    gh2 = gn2 = 0
    for f in (DATA / "test_cases_dh_base.json", DATA / "test_cases_ds_base.json"):
        h, n, _ = score(f, saved, tools["tuning"])
        gh2 += h
        gn2 += n
    print()
    print(f"  For contrast, the FITTED vocabulary on the same holdout cases:")
    print(f"     {gh2}/{gn2} = {100 * gh2 / max(gn2, 1):.1f}%   "
          f"(difference = {100 * (gh2 - grand_h) / max(gn2, 1):.1f} pp of fitting)")
    print()
    print("-" * 100)
    print("  How to read this")
    print("  ---------------")
    print("  Quote this only as retrospective tool-name vocabulary coverage.")
    print("  The gap is a coverage comparison, not a causal estimate of overfitting.")
    print()
    print("  This measures tool-name vocabulary coverage, not end-to-end detection.")
    print("  Prior exposure prevents calling this a blind test; no upper bound is proven.")
    print("=" * 100)

    out = REPO / "track2" / "eval" / "injecagent_holdout.json"
    out.write_text(json.dumps({
        "tuning_tools": sorted(tools["tuning"]), "holdout_tools": sorted(tools["holdout"]),
        "dropped_terms": dropped,
        "holdout_cases": grand_n, "holdout_flagged": grand_h,
        "holdout_rate": round(100 * grand_h / max(grand_n, 1), 2),
        "fitted_rate_on_same_cases": round(100 * gh2 / max(gn2, 1), 2),
        "measurement": "tool_name_vocabulary_coverage",
        "blind": False,
        "note": "Retrospective split after benchmark exposure; not detector recall, "
                "not an end-to-end benchmark and not a proven upper bound.",
    }, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
