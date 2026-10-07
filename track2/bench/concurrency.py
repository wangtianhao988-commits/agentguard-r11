"""Concurrency: does load change the verdict for a given call?

Why this is asked
-----------------
Every other measurement in this project drove the guard with one client, one request at
a time. The live path is not shaped like that: `InlineGuard` holds mutable per-instance
session state and the evidence store holds a shared file handle, both reached from the
event loop while other requests are in flight.

Two failures are invisible to a sequential run:

  * **load manufactures a finding.** Two sessions whose calls interleave could look like
    one session that read a credential and then sent data out.
  * **load hides a finding.** A refusal that only happens when the session arrives intact
    is a refusal that stops working under load.

The reference is therefore **the sequential verdict for the identical call**, not an
assumption about which calls should be flagged. That distinction is not pedantic: the
first version of this file assumed "benign -> clean" and "cross-tenant -> refused", and
both are wrong here -- cross-tenant reads are detected and *alerted* rather than blocked,
which is the documented design. It counted 71 correct detections as defects. **A test
that encodes its author's expectation instead of the system's contract measures the
author.**

    python track2/bench/concurrency.py --workers 16 --rounds 2
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
RANGE = REPO / "_scratch" / "competition" / "agentrange"

import httpx  # noqa: E402

BASE = "http://localhost:8101"
ENV = {k: "" for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                       "http_proxy", "https_proxy", "all_proxy", "no_proxy")}

#: The calls the deployment documents. Mixed deliberately: some the system should let
#: through, some it should flag, and one it should refuse -- and the test does not need
#: to know which is which, because the sequential run establishes that.
CALLS: List[Tuple[str, str, Dict[str, Any]]] = [
    ("customer-db", "query", {"tenant": "acme"}),
    ("customer-db", "query", {"tenant": "acme"}),
    ("monitoring", "query-metric", {"name": "cpu"}),
    ("knowledge", "search", {"q": "部署流程"}),
    ("gitlab", "get-pr", {"pr_id": 12}),
    ("threat-intel", "lookup", {"cve": "CVE-2026-0001"}),
    ("customer-db", "query", {"tenant": "globex"}),
    ("customer-db", "query", {"tenant": "initech"}),
]


def _key(server: str, tool: str, args: Dict[str, Any]) -> str:
    return f"{server}.{tool}:{json.dumps(args, sort_keys=True)}"


def _token(c: httpx.Client) -> str:
    r = c.post(f"{BASE}/login", json={"username": "lwang"}, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]


def _prime(c: httpx.Client, token: str, sid: str) -> None:
    """Establishes the session's identity, which the scope rule needs.

    Observation point A is where the guard sees who the caller is. Without it a session
    has no scope, and `rule_scope_violation` declines to guess.
    """
    try:
        c.post(f"{BASE}/run", json={"model": "opspilot-stub",
                                    "prompt": "请查询 ACME 工单 8842 的联系人记录。"},
               headers={"Authorization": f"Bearer {token}",
                        "X-Trace-Id": sid, "X-Instance-Id": sid}, timeout=90)
    except Exception:  # noqa: BLE001
        pass


def _call(c: httpx.Client, token: str, server: str, tool: str,
          args: Dict[str, Any], sid: str) -> str:
    """One MCP tool call through the guard, which is where the guard decides.

    The first version of this file drove `/run` with invented instance ids and reported
    a clean PASS on 72 requests with **zero guard decisions**: the llm-stub keys its
    script on `X-Instance-Id`, an invented id has no script, so the agent made no tool
    calls and nothing ever reached the guard. It measured 72 requests that did nothing.
    The load is applied here instead, where the decisions are.
    """
    try:
        r = c.post(f"{BASE}/mcp/{server}",
                   json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": tool.replace("-", "_"), "arguments": args}},
                   headers={"Authorization": f"Bearer {token}",
                            "X-Trace-Id": sid, "X-Instance-Id": sid},
                   timeout=90)
        body = r.text
        if "blocked by agent guard" in body:
            return "REFUSED"
        if r.status_code != 200:
            return f"HTTP {r.status_code}"
        return "ALLOWED"
    except Exception as e:  # noqa: BLE001
        return f"ERROR {type(e).__name__}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--evidence", default=str(RANGE / "evidence"))
    a = ap.parse_args()

    ev = Path(a.evidence)
    decisions = ev / "guard_decision.jsonl"
    before = _count(decisions)
    # The reference and the concurrent phase must be read from the SAME baseline. The
    # sequential calls happen first, so an offset taken after them would exclude the
    # reference; an offset of zero pulls in every previous run, which is how this file
    # once reported three cross-tenant calls as ALLOWED while the guard had flagged all
    # of them. This is the line between those two mistakes.
    baseline = before

    print("=" * 100)
    print("CONCURRENCY -- does load change the verdict for a given call?")
    print("=" * 100)
    tag = f"r{int(time.time())}-"
    print(f"  run tag {tag}")
    print(f"  workers {a.workers}   rounds {a.rounds}   "
          f"calls per round {len(CALLS)}   guard decisions before {before}")
    print()

    # -- 1. the reference: each call once, alone, on a fresh instance ----------------
    #
    # **A `/run` first, and that is not incidental.** The guard learns a session's
    # identity -- and therefore its scope -- from observation point A. `rule_scope_
    # violation` returns early when there is no declared scope, on the principle that
    # there is nothing to violate. So a client that calls MCP without ever calling
    # `/run` gets no scope checking at all.
    #
    # The first version of this file did exactly that, and every cross-tenant call came
    # back ALLOWED in the sequential reference too, which made the comparison vacuous:
    # 256 concurrent calls agreed with 8 sequential ones because all 264 were allowed.
    # **A concurrency test whose reference contains no non-trivial verdict cannot detect
    # a concurrency defect in one.**
    print("  -- sequential reference (each preceded by /run so the session has an identity) --")
    seq_sids: Dict[str, str] = {}
    with httpx.Client(headers=ENV, timeout=90) as c:
        tok = _token(c)
        for i, (server, tool, args) in enumerate(CALLS):
            sid = f"{tag}seq-{i}"
            _prime(c, tok, sid)
            _call(c, tok, server, tool, args, sid)
            # Recorded so the comparison below has a reference per CALL, not per run.
            # An earlier revision dropped this assignment and the section reported
            # "0 REFUSED, 0 ALERTED, 0 ALLOWED" -- an empty reference that would have
            # made any agreement vacuous. The guard's own refusal to call that a pass
            # is the only reason it was noticed.
            seq_sids[_key(server, tool, args)] = sid

    # -- 2. the same calls, concurrently --------------------------------------------
    observed: List[Tuple[str, str, str]] = []     # (key, session_id, http_verdict)
    lock = threading.Lock()
    t0 = time.perf_counter()

    def worker(w: int) -> None:
        with httpx.Client(headers=ENV, timeout=120) as c:
            try:
                tok = _token(c)
            except Exception as e:  # noqa: BLE001
                with lock:
                    observed.append(("<login>", f"login-failed-{w}"))
                return
            for rnd in range(a.rounds):
                for j, (server, tool, args) in enumerate(CALLS):
                    # One session PER CALL, matching the reference. The verdict the guard
                    # records is per SESSION and takes the highest severity, so sharing a
                    # session across the eight calls gave every call the verdict of the
                    # worst one -- the concurrent `acme` query came back ALERTED because
                    # the cross-tenant call in the same session was. The comparison
                    # looked like a concurrency defect and was a unit-of-analysis
                    # mismatch between the two sides.
                    sid = f"{tag}conc-{w}-{rnd}-{j}"
                    _prime(c, tok, sid)
                    v = _call(c, tok, server, tool, args, sid)
                    with lock:
                        observed.append((_key(server, tool, args), sid, v))

    threads = [threading.Thread(target=worker, args=(w,), daemon=True)
               for w in range(a.workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=900)
    wall = time.perf_counter() - t0
    time.sleep(4)

    # **Flush before reading, rather than waiting and hoping.**
    #
    # The verdicts are read out of `guard_decision.jsonl`, and the store buffers: a record
    # reaches disk when the buffer trips 64 entries or the 200 ms timer. Depending on that
    # timer made this test intermittent -- one run inside the full regression failed while
    # three standalone runs passed, because the read landed on a partial buffer. **The tail
    # is a property of when the file was read, not of what the guard decided**, and a test
    # whose result depends on that is measuring its own timing.
    #
    # `/debug/rotate` flushes every stream and reopens the handles, which makes the read
    # deterministic instead of likely.
    #
    # **Retried, because one flush was still not always enough.** The test passed five
    # standalone runs and failed once inside the full regression, and a harness that fails
    # one time in six for reasons unrelated to what it tests is a harness nobody can use.
    # The condition is explicit rather than a longer sleep: keep asking until the file
    # holds as many records as were sent, or give up and say so.
    expected = len(observed) + len(seq_sids)
    delta = 0
    for attempt in range(6):
        try:
            with httpx.Client(headers=ENV, timeout=30) as c:
                c.post(f"{BASE}/debug/rotate")
        except Exception:  # noqa: BLE001
            pass
        time.sleep(1.0)
        delta = _count(decisions) - before
        if delta >= expected:
            break
    if delta < expected:
        print(f"  NOTE: sent {expected} calls, the guard recorded {delta}. "
              f"The comparison below covers only what reached the file.")
    after = before + delta

    print()
    print(f"  {len(observed)} concurrent calls in {wall:.1f}s "
          f"({len(observed) / max(wall, 0.001):.0f} req/s)   "
          f"guard decisions {before} -> {after} (+{after - before})")

    # -- 3. did load change anything? ------------------------------------------------
    #
    # The comparison is (call -> verdict) on both sides, with the verdict taken from the
    # GUARD's own record. Reading it from the response body collapses ALERTED into
    # ALLOWED -- the guard forwards an alerted call and the caller sees the upstream
    # answer -- and the previous version reported every cross-tenant call as ALLOWED
    # while the guard had flagged all of them.
    guard = _verdicts(decisions, tag)
    print()
    print("  -- sequential verdict vs concurrent verdicts (from the guard's own record) --")
    counts: Dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    http_bad: List[Tuple[str, str]] = []
    for k, sid, http_v in observed:
        g = guard.get(sid)
        if g is None:
            # A call with no guard record AND a non-200 answer is a failed request, not
            # an undecided one. The two look identical when only the session id is kept,
            # which is why the previous version reported this as an anomaly for two
            # rounds without ever asking what the client was told.
            counts[k]["HTTP: " + http_v] += 1
            http_bad.append((sid, http_v))
        else:
            counts[k][g] += 1

    differs = 0
    for k, sid in seq_sids.items():
        want = guard.get(sid, "NO RECORD")
        got = counts.get(k, collections.Counter())
        extra = sorted(v for v in got if v != want)
        mark = "SAME" if not extra else "** DIFFERS **"
        if extra:
            differs += 1
        print(f"     {mark:<16} {k}")
        print(f"        sequential {want:<10} concurrent {dict(got)}")

    errors = counts.get("<login>", collections.Counter())
    unrecorded = sum(n for c in counts.values() for v, n in c.items() if v == "NO RECORD")
    refused_seq = sum(1 for sid in seq_sids.values() if guard.get(sid) == "REFUSED")
    alerted_seq = sum(1 for sid in seq_sids.values() if guard.get(sid) == "ALERTED")
    print()
    print(f"  sequential reference produced: {refused_seq} REFUSED, {alerted_seq} ALERTED, "
          f"{len(seq_sids) - refused_seq - alerted_seq} ALLOWED")
    if refused_seq == 0 and alerted_seq == 0:
        print("  ** the reference contains no non-trivial verdict, so agreement between")
        print("     the two sides proves nothing about concurrency -- say so rather than")
        print("     reporting a pass **")
    if http_bad:
        print(f"  {len(http_bad)} calls had no guard record; their HTTP answers were:")
        for v, n in collections.Counter(v for _, v in http_bad).most_common():
            print(f"     {n}x {v}")
    if errors:
        print(f"  login failures: {dict(errors)}")

    trivial = (refused_seq == 0 and alerted_seq == 0)
    ok = (differs == 0 and not unrecorded and not errors
          and _malformed(decisions) == 0 and not trivial)

    print()
    print("-" * 100)
    if ok:
        print("  PASS -- every concurrent call got the verdict the sequential call got.")
        print("  Concurrency neither manufactured nor hid a finding, and no request")
        print("  errored or produced an unparseable evidence line.")
    else:
        print(f"  FAIL -- {differs} call(s) changed verdict, {errors} errored, "
              f"{_malformed(decisions)} corrupt evidence lines.")
    print()
    print("  Scope: one guard process (single uvicorn worker; the event loop plus a lock")
    print("  on the evidence store), N threads from one host. This is not a capacity")
    print("  test and does not exercise a multi-worker deployment.")
    print("=" * 100)
    return 0 if ok else 1


def _count(p: Path) -> int:
    if not p.exists():
        return 0
    return sum(1 for l in p.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip())


def _verdicts(decisions: Path, tag: str) -> Dict[str, str]:
    """Per-session verdict as the GUARD recorded it, not as the response looked.

    The response body cannot carry an ALERT: the guard forwards the call and records the
    finding, and the caller sees the upstream answer either way. Reading the body
    therefore collapses ALERTED and ALLOWED into one label, and the first version of
    this file did exactly that -- it reported the cross-tenant calls as ALLOWED while the
    guard had flagged every one of them. **A verdict read from the wrong place is a
    verdict about the wrong thing.**
    """
    out: Dict[str, str] = {}
    if not decisions.exists():
        return out
    # **Filtered by this run's tag, not by a line offset.**
    #
    # A line offset looked equivalent and is not: the evidence store buffers and flushes
    # several streams on its own schedule, so a count taken just before the run can slice
    # between records that belong to it. That produced four「NO RECORD」 verdicts for calls
    # which a direct check of the evidence showed were both received and decided.
    # A tag cannot drift.
    lines = [l for l in decisions.read_text(encoding="utf-8", errors="replace").splitlines()
             if l.strip()]
    for line in lines:
        try:
            r = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        if r.get("point") != "mcp":
            continue
        sid = str(r.get("session_id") or "")
        if not sid.startswith(tag):
            continue
        sev = {f.get("severity") for f in r.get("findings") or []}
        if "BLOCK" in sev:
            cur = "REFUSED"
        elif "ALERT" in sev:
            cur = "ALERTED"
        else:
            cur = "ALLOWED"
        rank = {"ALLOWED": 0, "ALERTED": 1, "REFUSED": 2}
        if cur not in out or rank[cur] > rank[out[sid]]:
            out[sid] = cur
    return out


def _malformed(p: Path) -> int:
    if not p.exists():
        return 0
    bad = 0
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            json.loads(line)
        except Exception:  # noqa: BLE001
            bad += 1
    return bad


if __name__ == "__main__":
    raise SystemExit(main())
