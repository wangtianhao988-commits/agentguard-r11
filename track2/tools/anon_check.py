#!/usr/bin/env python
"""Anonymity compliance check for submission documents.

Why this is a separate tool
---------------------------
The brief's penalty for an anonymity breach is disqualification, not a deduction --
same class as the citation problem that consumed a whole chapter of the 题目5 audit.
It is also the kind of thing that is trivial to check and catastrophic to miss: a
single school name in an acknowledgement, or a GitHub URL under a personal account,
ends the entry.

The check is deliberately noisy. A false alarm costs a minute of reading; a miss costs
the competition.

    python track2/tools/anon_check.py competition_audit/*.md
    python track2/tools/anon_check.py --dir path/to/submission
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# High severity: these identify a person or institution directly.
#
# Two exclusions are baked into `email`, and both were learned by the checker
# flagging things that are not addresses at all:
#
#   * URL userinfo -- `https://trusted@evil.test/` is a host-confusion test case;
#   * **stack-frame signatures** -- `call_mcp@app.py:370` and `run@_asyncio.py:1089`
#     are py-spy's `function@file` format. The naive pattern read them as email and
#     raised three disqualification-level warnings on a report whose only sin was
#     quoting a captured stack.
#
# A checker that cries wolf is one people learn to skip, and this one guards a
# rule whose penalty is disqualification.
URL_USERINFO = re.compile(r"//[^\s/]*$")
SOURCE_FILE = re.compile(r"\.(py|pyc|js|ts|go|java|rb|rs|php|cs|c|cc|cpp|h|hpp)\b", re.I)

HIGH = [
    ("email", re.compile(r"(?<![/\w.+-])[\w.+-]+@[\w-]+\.[\w.]+")),
    ("phone (CN)", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("id card", re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")),
    ("home page / personal repo", re.compile(
        r"github\.com/(?!NVIDIA|secureagentics|cisco-ai-defense|nvidia)[A-Za-z0-9_-]+/?\b")),
    ("author list", re.compile(r"(作者|作者名单|完成人|指导教师|指导老师)\s*[:：]")),
    ("school name", re.compile(
        r"(大学|学院|研究院|研究所|University|College|Institute of Technology)")),
    ("unit / lab", re.compile(r"(实验室|课题组|研究中心|重点实验室)\s*[:：]?\s*\S")),
    ("student/staff id", re.compile(r"(学号|工号|一卡通)\s*[:：]")),
    ("competition id", re.compile(r"(参赛编号|队伍编号|报名编号)\s*[:：]?\s*\S")),
    ("city+school", re.compile(r"[\u4e00-\u9fa5]{2,8}(市|省)[\u4e00-\u9fa5]{2,10}(大学|学院)")),
]

# Low severity: context-dependent. Flagged for a human to decide.
LOW = [
    ("personal pronoun ownership", re.compile(r"(我们团队|本团队|我组|笔者所在)")),
    ("acknowledgement section", re.compile(r"^#+\s*(致谢|鸣谢|Acknowledg)", re.M)),
    ("funding / grant", re.compile(r"(基金|课题编号|项目编号)\s*[:：]?\s*\S")),
    ("named individual", re.compile(r"[\u4e00-\u9fa5]{2,4}(教授|老师|博士|同学)\s*")),
    ("windows user path", re.compile(r"C:\\\\?Users\\\\?([A-Za-z0-9_.-]+)")),
    ("home dir", re.compile(r"/(?:home|Users)/([A-Za-z0-9_.-]+)")),
]


def scan(path: Path) -> Tuple[List[Tuple[str, int, str, str]], List[Tuple[str, int, str, str]]]:
    high: List[Tuple[str, int, str, str]] = []
    low: List[Tuple[str, int, str, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001
        return [], [("unreadable", 0, str(e), "")]
    for i, line in enumerate(text.splitlines(), 1):
        for name, pat in HIGH:
            m = pat.search(line)
            if not m:
                continue
            hit = m.group(0)
            # A stack frame (`call_mcp@app.py:370`) is `function@file`, not an address.
            # Excluding it here rather than in the regex keeps the pattern readable and
            # makes the reason visible at the point of use.
            if name == "email" and SOURCE_FILE.search(hit):
                continue
            high.append((name, i, hit[:60], line.strip()[:100]))
        for name, pat in LOW:
            m = pat.search(line)
            if m:
                low.append((name, i, m.group(0)[:60], line.strip()[:100]))
    return high, low


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--dir", default=None, help="scan every .md/.txt/.tex under a directory")
    ap.add_argument("--quiet-low", action="store_true")
    a = ap.parse_args()

    files: List[Path] = [Path(p) for p in a.paths]
    if a.dir:
        files += sorted(p for p in Path(a.dir).rglob("*")
                        if p.is_file() and p.suffix.lower() in (".md", ".txt", ".tex", ".html"))

    if not files:
        print("nothing to scan. Pass files, or --dir <submission dir>.")
        return 2

    total_high = 0
    print("=" * 100)
    print("ANONYMITY COMPLIANCE CHECK")
    print("=" * 100)
    for f in files:
        high, low = scan(f)
        if not high and not low:
            print(f"\n  [clean] {f.name}")
            continue
        print(f"\n  {f.name}   HIGH={len(high)}  LOW={len(low)}")
        for name, ln, hit, ctx in high:
            print(f"     !! HIGH  L{ln:<5} {name:<26} {hit!r}")
            print(f"              {ctx}")
        total_high += len(high)
        if not a.quiet_low:
            for name, ln, hit, ctx in low:
                print(f"      · low   L{ln:<5} {name:<26} {hit!r}")

    print()
    print("-" * 100)
    if total_high:
        print(f"  {total_high} HIGH-severity hit(s). Each one must be resolved before submission:")
        print("  the brief's penalty for an anonymity breach is DISQUALIFICATION, not a deduction.")
    else:
        print("  No high-severity hits.")
    print()
    print("  What this cannot check:")
    print("   * de-anonymisation by *inference* -- a distinctive method name, a unique")
    print("     dataset, an unusual citation pattern. A human must read for that.")
    print("   * whether a figure or a PDF's metadata carries an author name. Check with")
    print("     `exiftool` / `pdfinfo` on the final PDF, not just the source text.")
    print("=" * 100)
    return 0 if total_high == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
