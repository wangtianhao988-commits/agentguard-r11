#!/usr/bin/env python
"""Aggregate a py-spy collapsed-stack profile into a ranked function table.

Kept as a file rather than an inline shell one-liner: the awk version of this got its
quoting mangled by the shell twice, and a profiler you cannot run reliably is worse
than no profiler.

    py-spy record --pid 1 --format raw --output prof.txt --duration 40
    python aggregate_profile.py prof.txt
"""
from __future__ import annotations

import collections
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: aggregate_profile.py <collapsed-stack-file> [top_n]")
        return 2
    path = Path(sys.argv[1])
    top_n = int(sys.argv[2]) if len(sys.argv) > 2 else 25
    if not path.exists():
        print(f"no profile at {path}")
        return 1

    total = 0
    leaf: collections.Counter = collections.Counter()
    incl: collections.Counter = collections.Counter()

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            stack, n = line.rsplit(" ", 1)
            n = int(n)
        except ValueError:
            continue
        frames = [f.strip() for f in stack.split(";") if f.strip()]
        if not frames:
            continue
        total += n
        # Leaf = what was executing. Inclusive = anywhere on the stack.
        leaf[frames[-1]] += n
        for f in set(frames):
            incl[f] += n

    print("=" * 100)
    print(f"SELF TIME -- {total} samples")
    print("=" * 100)
    for fn, n in leaf.most_common(top_n):
        bar = "#" * max(1, int(40 * n / max(total, 1)))
        print(f"  {100 * n / max(total, 1):5.1f}%  {bar:<40} {fn}")

    print()
    print("=" * 100)
    print("INCLUSIVE TIME (function anywhere on the stack)")
    print("=" * 100)
    for fn, n in incl.most_common(top_n):
        print(f"  {100 * n / max(total, 1):5.1f}%  {fn}")
    print()
    print("  Self time is where the CPU burns; inclusive time is who called it.")
    print("  A high-inclusive/low-self frame is waiting, not working.")
    print("=" * 100)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
