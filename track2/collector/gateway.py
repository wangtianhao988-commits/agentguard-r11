"""Observation gateway for the OpsPilot testbed.

Why a gateway rather than an SDK hook
-------------------------------------
The brief says the deliverable must be a **general algorithm**, and that the range
"只作为验证最终算法效果使用". Anything that requires editing the target agent is
therefore both fragile and the wrong shape: a real deployment protects an agent it
did not write.

Every hop in this range happens to be addressable by environment variable
(`opspilot-app/api/app.py:26` `LLM_BASE`, `:32-39` `MCP_*`;
`scenario-runner/runner.py:15-17` for the driver). So the whole of observation can
be obtained by **pointing those at this process** and forwarding. No target code
is modified; the same gateway would work against a different agent that reads its
endpoints from config -- which is the normal case.

Four observation points
-----------------------
    A  driver  -> agent     POST /run                  (prompt, skill, identity)
    B  agent   -> llm       POST /v1/chat/completions  (assembled messages: system
                                                        prompt, skill catalog,
                                                        loaded skill body,
                                                        tool calls + results)
    C  agent   -> MCP       POST /mcp/{server}         (JSON-RPC tools/call)
    D  egress  -> outside   (not proxied here; see note below)

B is where prompt-injection evidence actually lives: `api/app.py:101-108` puts the
**full body of the triggered SKILL.md** into the model context, so a poisoned skill
is visible on the wire even though nothing on disk looks wrong at call time.

D is deliberately NOT proxied. Egress leaves from `mcp-notes-sync` to `c2-sink` on
`egress-net`; capturing it would mean rewriting `C2_URL`, which is part of the
scenario definition rather than of the agent under protection. The backdoor is
still fully observable -- statically in the server source, and dynamically at C
when the hidden tool is invoked and at the agent when the beacon fires.

Design constraints taken from the brief
---------------------------------------
* **业务 0 中断**: forwarding is byte-faithful; a recording failure must never fail
  the request. Writing is best-effort.
* **响应时间 < 1 秒**: this is a local HTTP hop; measured overhead is reported by
  `bench.py`, not asserted here.
* **CPU < 5%**: recording is append-only JSONL, no parsing on the hot path beyond
  what the forwarder already does.
"""

from __future__ import annotations

import json
import asyncio
import collections
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from upstream import UpstreamClient
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from inline_guard import InlineGuard

# --------------------------------------------------------------------------
# evidence store
# --------------------------------------------------------------------------


class EvidenceStore:
    """Append-only JSONL, one file per observation point, with buffered writes.

    Deliberately dumb in structure -- a lock plus a write -- but **not** unbuffered.
    The first version called `flush()` on every record, which under the full-corpus
    replay (about 28k requests through the gateway in ~80 s) made the guard the most
    expensive process in the deployment: measured 37% of one core. Almost all of that
    was fsync-shaped overhead on tiny writes, not analysis.

    **That diagnosis did not survive re-measurement.** Buffering was added, and the
    figure is still 38% of one core -- see `bench/cpu_attribution.py`, which measured
    47.7 CPU-seconds over 28526 requests and found that removing 27% of the evidence
    bytes changed it by 0.2 percentage points. A `py-spy` sample of the guard then
    showed a FLAT profile: the largest single frame is the asyncio event loop at 15.5%,
    everything else is under 5%, spread across uvicorn's HTTP parser, anyio's stream
    wrappers, contextlib, httpcore and FastAPI's routing.

    So the honest statement is: **the cost is Python's async HTTP stack, per request,
    with no hotspot to fix.** Buffering is still correct -- it bounds loss rather than
    saving CPU -- but it is not the explanation it was written as.

    Buffering trades a bounded loss window for a large CPU saving:
      * flush when a stream reaches FLUSH_EVERY records, or
      * flush when FLUSH_MS has elapsed since the last write to that stream.
    At most FLUSH_EVERY records (or FLUSH_MS of traffic) can be lost on a hard kill.
    That window is stated rather than hidden, because "we might lose a few lines of
    audit log" is a decision the reader should get to see.
    """

    #: Cap on buffered records per stream when writes keep failing. Past this the
    #: oldest are dropped and COUNTED, so a permanently broken stream cannot become a
    #: memory leak and the loss is reported rather than guessed at.
    _MAX_PENDING = 4096

    FLUSH_EVERY = 64
    FLUSH_MS = 200.0

    def __init__(self, directory: str | Path) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._handles: Dict[str, Any] = {}
        self._pending: Dict[str, List[str]] = {}
        # Counts flushes per stream so the staleness check can run occasionally
        # instead of on every flush (it was 1.3% of all guard CPU in the profile).
        self._flush_count: Dict[str, int] = {}
        # Records lost to write failures, per stream. Zero unless something
        # is wrong; surfaced on /health so a lossy log cannot look like a quiet one.
        self._dropped: Dict[str, int] = {}
        self._last_flush: Dict[str, float] = {}

    def _handle(self, stream: str):
        h = self._handles.get(stream)
        if h is None:
            h = (self.dir / f"{stream}.jsonl").open("a", encoding="utf-8")
            self._handles[stream] = h
        return h

    def _stale(self, stream: str, h: Any) -> bool:
        """Has the file behind this handle been removed or replaced?

        **Throttled, because the profile said so.** A py-spy sample of the guard under
        a full replay put this function at 1.3% of all CPU -- for a safety check that
        only matters when an operator moves evidence files by hand, which happens
        between runs and never during one. Checking every 64th flush is still far more
        responsive than the situation requires and takes the cost off the profile.

        **`st_nlink == 0` is NOT sufficient here.** It is the textbook test for an
        unlinked-but-open file, and it silently failed on this deployment: Docker
        Desktop on Windows serves the bind mount through a file-sharing layer that
        does not preserve POSIX unlink semantics, so the container's `ls /evidence`
        correctly showed the file gone while `fstat` still reported nlink 1. The
        result was a guard writing every record into an anonymous inode for ten
        minutes while all its health endpoints reported fine.

        Path existence plus device/inode identity does not depend on that semantics.
        """
        self._flush_count[stream] = self._flush_count.get(stream, 0) + 1
        if self._flush_count[stream] % 64:
            return False
        p = self.dir / f"{stream}.jsonl"
        try:
            st_path = os.stat(p)
        except OSError:
            return True                      # gone: reopen and recreate
        try:
            st_fd = os.fstat(h.fileno())
        except OSError:
            return True
        if st_path.st_size < st_fd.st_size:
            return True                      # truncated or replaced by a smaller file
        try:
            return (st_path.st_dev, st_path.st_ino) != (st_fd.st_dev, st_fd.st_ino)
        except AttributeError:
            return False

    def _flush_locked(self, stream: str) -> None:
        buf = self._pending.get(stream)
        if not buf:
            return
        try:
            h = self._handle(stream)
            if self._stale(stream, h):
                try:
                    h.close()
                except Exception:
                    pass
                self._handles.pop(stream, None)
                h = self._handle(stream)
            h.write("".join(buf))
            h.flush()
        except Exception as e:  # noqa: BLE001
            # **The buffer is KEPT on failure. The first version cleared it.**
            #
            # `except: pass` followed by an unconditional `buf.clear()` meant a single
            # failed write discarded every record accumulated for that stream, silently.
            # A concurrency run produced MCP calls whose request bodies were captured and
            # whose decision was computed but whose audit record does not exist -- the
            # calls arrived and were judged, and the only surviving trace was the call
            # record itself. **An audit log that drops on a transient error is worse than
            # one that is merely late.**
            #
            # Keeping the buffer makes the next flush retry. The cap stops a permanently
            # broken stream from becoming a memory leak, and anything dropped is counted
            # and printed so it is reported rather than guessed at.
            if len(buf) > self._MAX_PENDING:
                excess = len(buf) - self._MAX_PENDING
                del buf[:excess]
                self._dropped[stream] = self._dropped.get(stream, 0) + excess
                print(f"[evidence] DROPPED {excess} records on {stream} after repeated "
                      f"write failures ({type(e).__name__}: {e}); "
                      f"{self._dropped[stream]} dropped in total")
            self._last_flush[stream] = time.monotonic()
            return
        buf.clear()
        self._last_flush[stream] = time.monotonic()

    def dropped(self) -> Dict[str, int]:
        """Records lost to write failures. Zero unless something is wrong."""
        with self._lock:
            return dict(self._dropped)

    def sweep(self) -> int:
        """Flush any stream whose buffer has been sitting longer than FLUSH_MS.

        **Without this the time bound in the class docstring is not real.** `FLUSH_MS`
        is only evaluated inside `write`, so it fires when the NEXT record arrives -- and
        if none does, the tail of the buffer waits indefinitely. A reader who looks at
        the evidence file after the traffic stops sees a file missing up to `FLUSH_EVERY`
        records, with nothing to say they are merely late.

        That is exactly how a concurrency test came to report "13 concurrent calls left
        no guard record": every one had been decided and buffered, and a forced rotate
        produced all thirteen. **The store promised a time bound and delivered a count
        bound, and the gap read as data loss.**

        Returns the number of streams flushed.
        """
        n = 0
        with self._lock:
            now = time.monotonic()
            for stream in list(self._pending):
                if not self._pending[stream]:
                    continue
                last = self._last_flush.get(stream, 0.0)
                # `self.FLUSH_MS`, not `FLUSH_MS`. **A method body does not see class
                # attributes as bare names** -- `write()` had it right and this did not,
                # so the sweeper raised NameError on its first iteration and every 250 ms
                # after that, for 34 consecutive ticks, while the counter beside it
                # recorded only "errors" and the reason went nowhere.
                if (now - last) * 1000 >= self.FLUSH_MS:
                    self._flush_locked(stream)
                    n += 1
        return n

    def rotate(self) -> Dict[str, Any]:
        """Close every handle so the next write reopens at the configured path.

        Call this after moving or deleting evidence files underneath a running
        gateway. Without it the store keeps writing to the file it opened, which may
        now live somewhere else entirely -- and the directory you are reading would
        look correct while receiving nothing.
        """
        with self._lock:
            for stream in list(self._pending):
                self._flush_locked(stream)
            names = list(self._handles)
            for h in self._handles.values():
                try:
                    h.close()
                except Exception:
                    pass
            self._handles.clear()
        return {"rotated": sorted(names), "dir": str(self.dir)}

    def write(self, stream: str, record: Dict[str, Any]) -> None:
        try:
            try:
                import orjson
                line = orjson.dumps(record, default=str).decode('utf-8') + '\n'
            except (ImportError, TypeError):
                line = json.dumps(record, ensure_ascii=False, default=str) + "\n"
            with self._lock:
                buf = self._pending.setdefault(stream, [])
                buf.append(line)
                now = time.monotonic()
                if (len(buf) >= self.FLUSH_EVERY
                        or (now - self._last_flush.get(stream, 0.0)) * 1000.0 >= self.FLUSH_MS):
                    self._flush_locked(stream)
        except Exception:
            # Serialization can fail before a record reaches the retained flush
            # buffer. Count that loss too; otherwise health reports no drops while
            # malformed/deep records silently disappear from the audit trail.
            with self._lock:
                self._dropped[stream]=self._dropped.get(stream,0)+1

    def flush_all(self) -> None:
        with self._lock:
            for stream in list(self._pending):
                self._flush_locked(stream)

    def close(self) -> None:
        self.flush_all()
        with self._lock:
            for h in self._handles.values():
                try:
                    h.close()
                except Exception:
                    pass
            self._handles.clear()


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------

AGENT_BASE = os.getenv("AGENT_BASE", "http://opspilot-app:8000")
LLM_BASE = os.getenv("LLM_BASE_UPSTREAM", "http://llm-stub:8000")
MCP_BASE = os.getenv("MCP_BASE", "http://mcp-{server}:8000")
# Framework upstream for observation E. Defaulted rather than required so the
# module still imports when only the agent path is being proxied -- a missing env
# var must not take down the whole gateway.
LANGFLOW_BASE = os.getenv("LANGFLOW_BASE_UPSTREAM", "http://langflow:7860")
RECORD_DIR = os.getenv("RECORD_DIR", "/evidence")

#: Which response streams to record. Default: only the one something reads.
#:   "used"  -> C only (tool return values are evidence; the rest are not)
#:   "meta"  -> status/latency for all, bodies for none
#:   "all"   -> previous behaviour, full traffic capture
#:   csv     -> an explicit set, e.g. "c,e"
_RESP_ENV = os.getenv("RECORD_RESPONSES", "used").strip().lower()
if _RESP_ENV in ("used", ""):
    RESPONSE_STREAMS = {"C"}
elif _RESP_ENV == "all":
    RESPONSE_STREAMS = "all"
elif _RESP_ENV == "meta":
    RESPONSE_STREAMS = "meta"
else:
    RESPONSE_STREAMS = {x.strip().upper() for x in _RESP_ENV.split(",") if x.strip()}
FORWARD_TIMEOUT = float(os.getenv("FORWARD_TIMEOUT", "15"))
#: Set to 0 to run as a pure pass-through, for measuring the proxy's own cost.
RECORD_ENABLED = os.getenv("RECORD_ENABLED", "1").strip().lower() not in ("0", "false", "no")

STORE = EvidenceStore(RECORD_DIR)
app = FastAPI(title="agentrange-observation-gateway")


class FrameworkOnly:
    """Do not expose a parallel tool proxy when the app uses native enforcement."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'http' and (scope['path'] in {'/run', '/login', '/v1/chat/completions'}
                                        or scope['path'].startswith('/mcp/')):
            response = JSONResponse({'error': 'agent routes disabled in framework-only mode'}, status_code=404)
            return await response(scope, receive, send)
        return await self.app(scope, receive, send)


if os.getenv('GUARD_FRAMEWORK_ONLY', '0') == '1':
    app.add_middleware(FrameworkOnly)


#: Strong reference to the evidence sweeper task.
#:
#: **`asyncio.create_task` returns a Task that the loop only holds WEAKLY.** The first
#: version of the sweeper dropped the return value:
#:
#:     asyncio.get_running_loop().create_task(_loop())      # <- collected
#:
#: and the task was garbage collected before it ever ran. Nothing reported it: no
#: exception, no log line, `sweep()` simply never happened, and the store kept behaving
#: exactly as it did before the fix -- flushing on write and holding the tail forever.
#: A test that waited 30 seconds for the buffer to drain saw the same number it started
#: with, which is what "the timer is not running" looks like from outside.
#:
#: That is the same shape as the other silent failures in this project: the code reads
#: as if it does the thing, and the thing does not happen.
_SWEEPER_TASK: Optional["asyncio.Task[None]"] = None


@app.on_event("startup")
async def _start_evidence_sweeper() -> None:
    """Make the store's FLUSH_MS an actual ceiling, not just an on-write fast path.

    See `EvidenceStore.sweep` for why this is needed: without a timer, a buffer whose
    traffic has stopped waits for the next record that may never come, and a reader sees
    a file that is quietly short.
    """
    global _SWEEPER_TASK

    async def _loop() -> None:
        while True:
            await asyncio.sleep(0.25)
            try:
                _DIAG["sweep_ticks"] += 1
                n = STORE.sweep()
                _DIAG["sweep_flushes"] += n
                _DIAG["pending_streams"] = sum(1 for v in STORE._pending.values() if v)
            except Exception as e:  # noqa: BLE001
                # **The error text is kept, not swallowed.** The first version of this
                # loop counted the failure and printed nothing, so the counter said 34
                # errors and the reason was nowhere -- which is the same "no record of
                # why" shape this whole file keeps running into.
                _DIAG["sweep_errors"] += 1
                _DIAG["sweep_last_error"] = f"{type(e).__name__}: {e}"

    # The reference is the whole point. Binding it to a module-level name keeps the task
    # alive; `_DIAG["sweep_ticks"]` makes "is it running" answerable from outside.
    _SWEEPER_TASK = asyncio.get_running_loop().create_task(_loop())


class PhaseTimer:
    """Per-phase accumulated time, exposed at /debug/timing.

    Added because M5 ("CPU < 5%") was the one metric that measured as failing and
    two rounds of optimisation by guesswork -- buffering the evidence writes, then
    removing a duplicate JSON serialisation -- both changed the number by less than
    the noise. Guessing at a hot path is how you make a change that looks like an
    improvement and is not, so the guard now reports where its own time goes.

    This is deliberately part of the shipped component rather than a throwaway
    profiler hook: a guard that cannot say what it costs is a guard nobody can
    budget for.
    """

    def __init__(self) -> None:
        self._acc: Dict[str, int] = {}
        self._n: Dict[str, int] = {}
        self._lock = threading.Lock()

    def add(self, phase: str, ns: int) -> None:
        with self._lock:
            self._acc[phase] = self._acc.get(phase, 0) + ns
            self._n[phase] = self._n.get(phase, 0) + 1

    def snapshot(self, reset: bool = False) -> Dict[str, Any]:
        with self._lock:
            acc = dict(self._acc)
            n = dict(self._n)
            if reset:
                self._acc.clear()
                self._n.clear()
        total = sum(acc.values()) or 1
        rows = {}
        for k in sorted(acc, key=lambda x: -acc[x]):
            rows[k] = {"total_ms": round(acc[k] / 1e6, 2),
                       "calls": n[k],
                       "mean_us": round(acc[k] / max(n[k], 1) / 1e3, 2),
                       "share": round(acc[k] / total, 4)}
        return {"phases": rows, "total_ms": round(total / 1e6, 2)}


#: Diagnosis state for the concurrency anomaly -- see the counters in `obs_c_mcp`.
#:
#: Temporary and labelled as such. It answers "how far does the handler get" rather
#: than "what does the handler decide", and it comes out once the anomaly is located.
#: Five hypotheses were refuted from the artefacts alone; this counts the code path
#: itself, which is the next thing to try when reading the output stops working.
_DIAG: Dict[str, int] = collections.defaultdict(int)
_DIAG_SEEN: set = set()
_DIAG_LOCK = threading.Lock()

TIMER = PhaseTimer()

# --------------------------------------------------------------------------
# load the tool profile the inventory produced
# --------------------------------------------------------------------------
#
# **This call was missing, and its absence made a headline claim untrue.**
#
# `session.load_tool_meta()` had existed since the capability model was written and was
# never called from the collector. Consequence: in the live path `_TOOL_META` stayed
# empty, `code_caps` was always the empty set, and the capability a rule saw came from
# the pinned `CAPABILITIES` table rather than from static analysis of the
# implementation. `generalization/code_backdoor.py` still passed -- but it feeds
# `code_caps` in by hand and exercises `capabilities_of()`, so it verified the FUNCTION
# and never the PIPELINE. A backdoor whose name, schema and description are all
# innocuous was invisible in a real deployment.
#
# With this wired, the inventory's `code_caps` reaches the detector and the
# "(contract - constraints) union implementation" rule is the one that actually runs.
INVENTORY_PATH = os.getenv("INVENTORY_PATH", "/evidence/inventory.json")
try:
    import session as _session_mod
    N_TOOLS_LOADED = _session_mod.load_tool_meta(INVENTORY_PATH)
    _session_mod.load_skill_catalog(INVENTORY_PATH)
except Exception as _e:  # noqa: BLE001
    N_TOOLS_LOADED = 0
    print(f"[gateway] tool profile unavailable ({type(_e).__name__}: {_e}); "
          f"capabilities fall back to the pinned table plus the declaration")

#: Inline enforcement. `GUARD_ENFORCE=0` runs the guard in audit mode: it evaluates
#: and records every call but refuses none. That mode exists for two reasons -- the
#: brief's 业务 0 中断 requirement cannot be demonstrated without comparing against an
#: unenforced baseline, and an operator rolling out a guard needs a way to see what it
#: WOULD have blocked before letting it block.
from task_policy import TaskPolicies
_TASK_POLICY_PATH = os.getenv('GUARD_TASK_POLICY_PATH', '')
if _TASK_POLICY_PATH and not os.getenv('GUARD_APP_IMPORT'):
    raise RuntimeError('Task policies require the authenticated native application integration')
GUARD = InlineGuard(
    enabled=os.getenv("GUARD_ENFORCE", "1").strip().lower() not in ("0", "false", "no"),
    task_policies=TaskPolicies.load(_TASK_POLICY_PATH) if _TASK_POLICY_PATH else None)


@app.get("/debug/timing")
async def debug_timing(reset: bool = False) -> Dict[str, Any]:
    """Where the guard spends its own time. `?reset=true` zeroes the counters."""
    return TIMER.snapshot(reset=reset)


@app.get("/debug/guard")
async def debug_guard(reset: bool = False) -> Dict[str, Any]:
    """Enforcement counters: checked / blocked / alerted / allowed / errors.

    `errors` is the one to watch. The guard fails open by design -- a guard bug must
    not become an outage -- so without this counter a completely dead guard would look
    exactly like a quiet one.
    """
    return GUARD.snapshot(reset=reset)


@app.get("/debug/diag")
async def debug_diag(reset: bool = False) -> Dict[str, Any]:
    """Stage counters for the concurrency anomaly. Temporary; see `_DIAG`."""
    with _DIAG_LOCK:
        out: Dict[str, Any] = dict(_DIAG)
        out["mcp_unique_rids"] = len(_DIAG_SEEN)
        if reset:
            for k in list(_DIAG):
                _DIAG[k] = 0
            _DIAG_SEEN.clear()
    return out


@app.post("/debug/rotate")
async def debug_rotate() -> Dict[str, Any]:
    """Reopen every evidence file. Call after moving or deleting evidence on disk."""
    return STORE.rotate()


@app.on_event("shutdown")
def _flush_on_shutdown() -> None:
    # Without this the tail of the evidence is lost on every clean stop -- which is
    # exactly the part covering the most recent attack.
    STORE.close()

# An ASYNC client, used with `await`.
#
# The first version used a synchronous `httpx.Client` inside `async def` handlers.
# That blocks the event loop, and in this topology it deadlocks immediately:
#
#     driver -> gateway /run  (handler blocks the loop for the whole agent turn)
#     agent  -> gateway /v1/chat/completions  (queued, never dispatched)
#     agent's own `timeout=10` fires -> HTTP 500
#
# i.e. the observation layer caused an outage -- a direct violation of the brief's
# "业务 0 中断". A proxy MUST NOT serialise the requests it proxies.
#
# The pool limits are explicit, and they matter more than they look.
#
# `httpx.AsyncClient(timeout=...)` alone leaves the default
# `Limits(max_connections=100, max_keepalive_connections=20)`. At the replay's
# ~228 req/s spread over four upstream services, 20 keep-alive slots cannot hold the
# connections open, so the client tears down and re-establishes TCP connections
# continuously. Measured: 47.7 CPU-seconds for 28526 requests = **1.67 ms of CPU each**,
# which is pathological for a proxy. Nothing else in the request path comes close --
# evidence writing costs 0.2 percentage points for 27% of the bytes, and the detection
# rules cost 30 microseconds.
CLIENT = UpstreamClient(FORWARD_TIMEOUT)


@app.on_event('shutdown')
async def _close_upstream_client() -> None:
    await CLIENT.aclose()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _rid() -> str:
    return uuid.uuid4().hex[:12]


# --------------------------------------------------------------------------
# observation A -- driver -> agent
# --------------------------------------------------------------------------


@app.post("/run")
async def obs_a_run(request: Request) -> Response:
    body, raw = await _body_and_raw(request)
    rid = _rid()
    hdrs = _selected_headers(request)
    # Tell the guard about the session context BEFORE any tool call can arrive, so
    # identity and skill are known when the first call is judged.
    iid = hdrs.get("x-trace-id") or hdrs.get("x-instance-id") or rid
    # Generated correlation must be propagated downstream, not just stored here.
    raw_headers = list(request.scope["headers"])
    if not hdrs.get("x-trace-id"):
        raw_headers.append((b"x-trace-id", iid.encode("ascii")))
        request.scope["headers"] = raw_headers
        request.__dict__.pop("_headers", None)
        hdrs["x-trace-id"] = iid
    GUARD.observe_run(iid, hdrs, body or {})
    rec = {
        "obs": "A", "rid": rid, "ts": _now(),
        "path": "/run",
        "headers": hdrs,
        "body": body,
    }
    _record("A_agent_ingress", rec)
    return await _forward(request, f"{AGENT_BASE}/run", "A", rid, raw)


@app.post("/login")
async def obs_a_login(request: Request) -> Response:
    body, raw = await _body_and_raw(request)
    rid = _rid()
    _record("A_agent_ingress",
                {"obs": "A", "rid": rid, "ts": _now(), "path": "/login", "body": body})
    return await _forward(request, f"{AGENT_BASE}/login", "A", rid, raw)


@app.get("/health")
async def health() -> Dict[str, Any]:
    # Gateway health is separate from upstream health on purpose: a judge asking
    # "is the guard up" must not get "yes" because the agent happens to be up.
    up: Dict[str, Any] = {}
    for name, url in (("agent", f"{AGENT_BASE}/health"), ("llm", f"{LLM_BASE}/health")):
        try:
            r = await CLIENT.get(url, timeout=3)
            up[name] = {"ok": r.status_code == 200, "status": r.status_code}
        except Exception as e:  # noqa: BLE001
            up[name] = {"ok": False, "error": type(e).__name__}
    return {"status": "ok", "upstreams": up, "record_dir": str(STORE.dir),
            "http_transport": CLIENT.backend,
            # Surfaced so a failed profile load is VISIBLE. Without it, an empty
            # `_TOOL_META` looked exactly like a detector with nothing to say -- the
            # failure mode this project has paid for repeatedly.
            # Records lost to write failures. Surfaced because a lossy audit log
            # that looks like a quiet one is the failure this project keeps meeting.
            "records_dropped": STORE.dropped(),
            "tool_profile_loaded": N_TOOLS_LOADED,
            "inventory_path": INVENTORY_PATH}


# --------------------------------------------------------------------------
# observation B -- agent -> llm
# --------------------------------------------------------------------------


@app.post("/v1/chat/completions")
async def obs_b_llm(request: Request) -> Response:
    body, raw = await _body_and_raw(request)
    rid = _rid()
    hdrs = _selected_headers(request)
    msgs = (body or {}).get("messages") or []
    # The skill catalog reaches the guard here: it is the only place the declared
    # `allowed-tools` of each skill is visible, and `undeclared-skill-capability`
    # needs it to compare a promise against behaviour.
    iid = hdrs.get("x-trace-id") or hdrs.get("x-instance-id") or rid
    GUARD.observe_skill_catalog(iid, msgs)
    # Summarise the context on the hot path (cheap) but keep the full messages:
    # the poisoned skill body lives in a system message and is the whole point of
    # observing this hop.
    rec = {
        "obs": "B", "rid": rid, "ts": _now(),
        "headers": hdrs,
        "n_messages": len(msgs),
        "roles": [m.get("role") for m in msgs if isinstance(m, dict)],
        "tools": [t.get("function", {}).get("name") for t in (body or {}).get("tools") or []],
        "messages": msgs,
    }
    _record("B_llm_request", rec)
    return await _forward(request, f"{LLM_BASE}/v1/chat/completions", "B", rid, raw)


# --------------------------------------------------------------------------
# observation C -- agent -> MCP
# --------------------------------------------------------------------------


@app.post("/mcp/{server}")
async def obs_c_mcp(server: str, request: Request) -> Response:
    body, raw = await _body_and_raw(request)
    rid = _rid()
    hdrs = _selected_headers(request)
    params = (body or {}).get("params") or {}
    tool = params.get("name")
    arguments = params.get("arguments", {})
    rec = {
        "obs": "C", "rid": rid, "ts": _now(), "server": server,
        "headers": hdrs,
        "jsonrpc_method": (body or {}).get("method"),
        "tool": tool,
        "arguments": arguments,
        "body": body,
    }
    _record("C_mcp_call", rec)

    # -- DIAGNOSIS --------------------------------------------------------
    # Counters for a concurrency anomaly that survived five refuted hypotheses.
    #
    # A concurrent run produces 8-12 MCP calls with a `C_mcp_call` record and no
    # `guard_decision` record. The bodies are complete, `tool` is non-empty and
    # byte-identical in shape to calls that succeed, the client gets a response, no
    # exception reaches the log, and the evidence store reports zero dropped records.
    # Reasoning from the artefacts has not located it, so the code path now counts
    # itself: which of the stages below each request actually reaches.
    with _DIAG_LOCK:
        _DIAG["mcp_entered"] += 1
    if (body or {}).get("method") == "tools/call" and tool:
        with _DIAG_LOCK:
            _DIAG["mcp_branch_taken"] += 1
    try:
        _DIAG_SEEN.add(rid)
    except Exception:  # noqa: BLE001
        pass

    # -- ENFORCEMENT POINT ------------------------------------------------
    # Judge before forwarding. A blocked call is NOT forwarded: the tool does not
    # run, which is the difference between detection and defence.
    if (body or {}).get("method") == "tools/call" and tool:
        iid = hdrs.get("x-trace-id") or hdrs.get("x-instance-id") or rid
        with _DIAG_LOCK:
            _DIAG["mcp_before_check"] += 1
        decision = GUARD.check_tool_call(iid, server, tool, arguments, call_id=rid)
        with _DIAG_LOCK:
            _DIAG["mcp_after_check"] += 1
        # Deterministic stack capture at the decision point: the application is
        # blocked on this very call right now, so its stack IS the chain of interest.
        await _stack_for_decision(rid, {"point": "mcp", "server": server,
                                        "tool": tool, "session_id": iid},
                                  decision.action)
        with _DIAG_LOCK:
            _DIAG["mcp_decision_recorded"] += 1
        _record("guard_decision", {
            "obs": "G", "rid": rid, "ts": _now(), "point": "mcp",
            "server": server, "tool": tool,
            **decision.to_json(),
        })
        if decision.blocked:
            # A JSON-RPC error, not an HTTP error and not an exception. Every agent
            # loop already handles a failed tool call, so a refusal degrades the turn
            # instead of breaking it -- which is what "业务 0 中断" requires of a
            # blocking mechanism. The message names the rule so the refusal is
            # arguable rather than mysterious.
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": (body or {}).get("id"),
                "error": {
                    "code": -32000,
                    "message": "blocked by agent guard",
                    "data": {"rule": decision.findings[0].rule_id if decision.findings else "",
                             "reason": decision.reason,
                             "rid": rid},
                },
            }, status_code=200)

    upstream = MCP_BASE.format(server=server) + "/mcp"
    response = await _forward(request, upstream, "C", rid, raw, server=server)
    if (body or {}).get("method") == "tools/call" and tool:
        try:
            result = json.loads(response.body)
        except (ValueError, TypeError):
            result = {"__raw__": response.body.decode("utf-8", "replace")[:4000]}
        GUARD.observe_tool_result(iid, rid, result, ok=response.status_code < 400)
    return response


@app.get("/mcp/{server}/health")
async def obs_c_health(server: str) -> Response:
    try:
        r = await CLIENT.get(MCP_BASE.format(server=server) + "/health", timeout=3)
        return Response(content=r.content, status_code=r.status_code,
                        media_type=r.headers.get("content-type"))
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"ok": False, "error": type(e).__name__}, status_code=502)


# --------------------------------------------------------------------------
# observation E -- driver -> framework (Langflow)
# --------------------------------------------------------------------------
#
# Category-1 attacks never touch the agent: they hit the orchestration framework
# directly (`/api/v1/validate/code`, `/api/v2/files`). Two of the seven scenarios and
# 24 of the 80 positives live entirely here, so an agent-side gateway alone would be
# blind to ~30% of the corpus. Routing the framework through the same process also
# gives the framework WAF and the agent guard one shared evidence stream.
#
# The path after the prefix is passed through unchanged, INCLUDING method, query
# string and multipart body, because the upload scenario's evidence is a filename
# (`exploit_5027.py:3` builds `../../../../..` + target).


@app.api_route("/langflow/{path:path}",
               methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def obs_e_langflow(path: str, request: Request) -> Response:
    rid = _rid()
    raw = await request.body()
    body: Any = None
    if raw:
        try:
            body = json.loads(raw)
        except Exception:  # noqa: BLE001
            # Multipart uploads are not JSON. Decode leniently so the filename
            # survives into evidence -- that filename IS the exploit.
            body = {"__raw_preview__": raw[:2000].decode("utf-8", "replace"),
                    "__bytes__": len(raw)}
    rec = {
        "obs": "E", "rid": rid, "ts": _now(), "path": f"/langflow/{path}",
        "method": request.method,
        "query": dict(request.query_params),
        "headers": _selected_headers(request),
        "body": body,
        "content_type": request.headers.get("content-type", ""),
    }
    if "multipart/form-data" in (request.headers.get("content-type") or ""):
        # Pull the filename out of the multipart header block. Cheap, and it is the
        # single most valuable field for the traversal scenario.
        head = raw[:1200].decode("utf-8", "replace")
        for token in ("filename=", "name="):
            i = head.find(token)
            if i >= 0:
                rec.setdefault("multipart_fields", {})[token.rstrip("=")] = \
                    head[i + len(token):].split("\r\n")[0].strip('"')
    _record("E_framework_call", rec)

    # -- ENFORCEMENT POINT (framework) ------------------------------------
    # Category-1 attacks bypass the agent entirely, so the agent-side guard above
    # never sees them. Without this the guard would score well on the corpus and let
    # the framework exploits through -- which is exactly the shape of a defence that
    # was tuned to a test rather than to a threat.
    fw_decision = GUARD.check_framework_call(
        request.method, path, dict(request.query_params), body,
        raw[:1200].decode("utf-8", "replace"))
    _record("guard_decision", {
        "obs": "G", "rid": rid, "ts": _now(), "point": "framework",
        "path": f"/langflow/{path}", "method": request.method,
        **fw_decision.to_json(),
    })
    # A refused framework request never reaches the upstream handler. The
    # Agent worker's sidecar stack is unrelated to this request: preserve the
    # real gateway interception stack and explicitly name its target and stage.
    if CAPTURE_ON != "off" and (fw_decision.action != "ALLOW" or CAPTURE_ON == "always"):
        from native_stack import capture
        _record("code_stack", {"obs": "S", "rid": rid, "ts": _now(),
            "point": "framework", "path": f"/langflow/{path}",
            "method": request.method, "capture_target": "guard-gateway",
            "stage": "pre-upstream", "upstream_forwarded": not fw_decision.blocked,
            **capture()})
    if fw_decision.blocked:
        # 200 with an application-level error body, NOT 403.
        #
        # The first version returned 403, and the full-corpus replay died after 135
        # decisions: the driver calls `raise_for_status()` (scenario-runner/runner.py)
        # and a transport-level failure aborts its loop, so one blocked exploit stopped
        # the remaining 5190 events from ever running. That is a guard turning a refused
        # action into an outage of the caller, which is precisely what "业务 0 中断"
        # forbids -- and it is also inconsistent with the agent-side path, which refuses
        # a tool call inside a 200 JSON-RPC error because every agent loop already
        # handles a failed tool call.
        #
        # So both enforcement points now refuse at the application layer. The block is
        # loud in the audit log and in a response header; it is quiet on the wire. That
        # is the right default for a guard: the attacker's step fails, the session
        # survives, and an operator can still see exactly what happened.
        return JSONResponse(
            {"detail": "request rejected by agent guard",
             "errors": [{"rule": f.rule_id, "reason": f.summary}
                        for f in fw_decision.findings] or
                       [{"rule": "", "reason": fw_decision.reason}]},
            status_code=200,
            headers={"X-Guard-Blocked": (fw_decision.findings[0].rule_id
                                         if fw_decision.findings else "guard"),
                     "X-Guard-Rid": rid})

    url = f"{LANGFLOW_BASE}/{path}"
    fwd_headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in ("host", "content-length", "connection")}
    fwd_headers["X-Guard-Rid"] = rid
    t0 = time.perf_counter()
    try:
        r = await CLIENT.request(request.method, url, headers=fwd_headers, content=raw or None,
                                 params=dict(request.query_params))
        _record("E_response", {
            "obs": "E", "rid": rid, "ts": _now(), "upstream": url,
            "status": r.status_code, "latency_ms": round((time.perf_counter() - t0) * 1000, 3),
            "body": _safe_json(r),
        })
        return Response(content=r.content, status_code=r.status_code,
                        media_type=r.headers.get("content-type"))
    except Exception as e:  # noqa: BLE001
        _record("E_response", {"obs": "E", "rid": rid, "ts": _now(), "upstream": url,
                                   "error": f"{type(e).__name__}: {e}"})
        return JSONResponse({"error": "upstream unreachable", "detail": str(e)}, status_code=502)


# --------------------------------------------------------------------------
# forwarding
# --------------------------------------------------------------------------


def _selected_headers(request: Request) -> Dict[str, str]:
    """Headers worth keeping as evidence. Not everything -- auth tokens rotate."""
    keep = {"x-instance-id", "x-trace-id", "x-acting-user", "x-acting-role",
            "authorization", "content-type", "user-agent"}
    return {k.lower(): v for k, v in request.headers.items() if k.lower() in keep}


async def _json_or_raw(request: Request) -> Any:
    raw = await request.body()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:  # noqa: BLE001
        return {"__raw__": raw.decode("utf-8", "replace")}


async def _body_and_raw(request: Request) -> Any:
    """Read the body ONCE and return both views.

    The first version read the body, parsed it, then **re-serialised it** to forward.
    The observation-B payload embeds the whole growing `messages` array, so that
    second `json.dumps` was the single most expensive thing the guard did -- and it
    was pure waste, because the original bytes were already in hand and are exactly
    what the upstream expects. Forwarding the raw bytes removes one full
    serialisation of every request under observation.
    """
    t0 = time.perf_counter_ns()
    raw = await request.body()
    TIMER.add("read_body", time.perf_counter_ns() - t0)
    if not raw:
        return None, b""
    t0 = time.perf_counter_ns()
    try:
        parsed = json.loads(raw)
    except Exception:  # noqa: BLE001
        parsed = {"__raw__": raw.decode("utf-8", "replace")}
    TIMER.add("parse_json", time.perf_counter_ns() - t0)
    return parsed, raw


def _record(stream: str, record: Dict[str, Any]) -> None:
    """Serialise + enqueue, timed separately from the forward.

    `RECORD_ENABLED=0` turns the guard into a pure pass-through. That mode exists to
    answer a measurement question, not as a feature: it separates "the cost of being
    an HTTP proxy" from "the cost of being an observing guard". Without that split an
    M5 figure cannot say which of the two a reader is being asked to accept.
    """
    if not RECORD_ENABLED:
        return
    t0 = time.perf_counter_ns()
    STORE.write(stream, record)
    TIMER.add("record_evidence", time.perf_counter_ns() - t0)


# --------------------------------------------------------------------------
# application call stack (observation S)
# --------------------------------------------------------------------------
#
# The brief's J2 requires the "应用内函数栈" among the evidence for a finding. The
# audit initially concluded that was unobtainable: the range logs no stacks, and the
# brief forbids the `/admin/trajectories` answer endpoint. That was right about
# recovering stacks from logs and wrong as a general claim -- the process is alive and
# a stack can be read from it.
#
# The capture is deterministic, not a sample. At the instant the guard intercepts a
# `tools/call`, the application is BLOCKED waiting for that response, so its stack is
# precisely the chain that produced the action under judgement.
#
# It is issued as a background task. `py-spy dump` costs hundreds of milliseconds --
# untenable inline under a one-second budget -- and the decision must not wait for
# evidence about it. The target stays blocked until the guard forwards, so the stack
# does not go stale in the meantime.

STACK_URL = os.getenv("STACK_URL", "").strip()
STACK_BUDGET_SECONDS = 0.5
_stack_tasks: set = set()


#: Only capture a stack when there is something to attach it to.
#:
#: Capturing asynchronously after forwarding was the first attempt and it produced
#: the IDLE worker stack: py-spy attaches a few milliseconds later, by which time the
#: application has already received its response and gone back to waiting for work.
#: The window in which the stack is meaningful is exactly the window in which the
#: application is blocked on us -- i.e. before we answer.
#:
#: So the capture is synchronous and happens before the response leaves, and only for
#: calls that produced a finding. Benign traffic -- 6449 of 6546 calls -- pays nothing,
#: and the calls that matter pay ~14 ms, against a one-second budget.
CAPTURE_ON = os.getenv("STACK_CAPTURE_ON", "finding").strip().lower()  # finding|always|off


async def _capture_stack(rid: str, context: Dict[str, Any]) -> None:
    if not STACK_URL:
        with _DIAG_LOCK:
            _DIAG["stack_no_url"] += 1
        return
    try:
        # Evidence capture cannot consume the one-second response budget when
        # stackd stalls. Bound the entire exchange, including connection/read.
        r = await asyncio.wait_for(CLIENT.get(STACK_URL, timeout=6),
                                   timeout=STACK_BUDGET_SECONDS)
        payload = r.json()
    except Exception as e:  # noqa: BLE001
        payload = {"error": f"{type(e).__name__}: {e}"}
        with _DIAG_LOCK:
            _DIAG["stack_http_error"] += 1
    try:
        _record("code_stack", {"obs": "S", "rid": rid, "ts": _now(),
                               **context, **payload})
        with _DIAG_LOCK:
            _DIAG["stack_recorded"] += 1
    except Exception:  # noqa: BLE001
        with _DIAG_LOCK:
            _DIAG["stack_record_failed"] += 1


async def _stack_for_decision(rid: str, context: Dict[str, Any], action: str) -> None:
    """Capture before the response leaves, so the application is still blocked."""
    with _DIAG_LOCK:
        _DIAG["stack_called"] += 1
    if not STACK_URL or CAPTURE_ON == "off":
        with _DIAG_LOCK:
            _DIAG["stack_skipped_no_url"] += 1
        return
    if CAPTURE_ON == "finding" and action == "ALLOW":
        with _DIAG_LOCK:
            _DIAG["stack_skipped_allow"] += 1
        return
    t0 = time.perf_counter_ns()
    await _capture_stack(rid, context)
    TIMER.add("capture_stack", time.perf_counter_ns() - t0)


def _spawn_stack_capture(rid: str, context: Dict[str, Any]) -> None:
    """Unconditional background capture. Kept for `STACK_CAPTURE_ON=always`."""
    if not STACK_URL:
        return
    try:
        t = asyncio.get_running_loop().create_task(_capture_stack(rid, context))
        _stack_tasks.add(t)
        t.add_done_callback(_stack_tasks.discard)
    except RuntimeError:
        pass


async def _forward(request: Request, url: str, obs: str, rid: str, raw: bytes,
                   parsed: Any = None, server: Optional[str] = None) -> Response:
    fwd_headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in ("host", "content-length", "connection")}
    fwd_headers["X-Guard-Rid"] = rid
    payload = raw if (raw and request.method != "GET") else None

    t0 = time.perf_counter()
    try:
        r = await CLIENT.request(request.method, url, headers=fwd_headers, content=payload,
                                 params=dict(request.query_params))
        dt_ms = (time.perf_counter() - t0) * 1000.0
        TIMER.add("forward_upstream", int(dt_ms * 1e6))
        # Response bodies are recorded only where something reads them.
        #
        # Measured: `A_response` (4.7 MB), `B_response` (6.4 MB) and `E_response` are
        # referenced by ZERO of the detector, evaluator and report modules, while
        # costing a JSON parse of the body plus a JSON serialisation of the record on
        # every single request. `C_response` IS read -- it carries tool return values,
        # which are evidence (the `.env` content in the exfiltration scenario).
        #
        # So the default records what is used. This is not a measurement trick: no
        # detection, no audit section and no reported number depends on the dropped
        # streams, and `RECORD_RESPONSES=all` restores the previous behaviour for
        # anyone who wants the full traffic capture.
        if RESPONSE_STREAMS == "all" or obs in RESPONSE_STREAMS:
            _record(f"{obs}_response", {
                "obs": obs, "rid": rid, "ts": _now(), "upstream": url,
                "status": r.status_code, "latency_ms": round(dt_ms, 3),
                "body": _safe_json(r),
            })
        elif RESPONSE_STREAMS == "meta":
            # Keep the shape of the traffic -- status and latency -- without paying to
            # parse and re-serialise a body nobody reads.
            _record(f"{obs}_response", {
                "obs": obs, "rid": rid, "ts": _now(), "upstream": url,
                "status": r.status_code, "latency_ms": round(dt_ms, 3),
                "body_bytes": len(r.content or b""),
            })
        return Response(content=r.content, status_code=r.status_code,
                        media_type=r.headers.get("content-type"))
    except Exception as e:  # noqa: BLE001
        dt_ms = (time.perf_counter() - t0) * 1000.0
        TIMER.add("forward_upstream", int(dt_ms * 1e6))
        _record(f"{obs}_response", {
            "obs": obs, "rid": rid, "ts": _now(), "upstream": url,
            "error": f"{type(e).__name__}: {e}", "latency_ms": round(dt_ms, 3),
        })
        # 502, and the agent sees a failed tool call rather than a hang. The
        # brief requires the guard not to interrupt business; when the UPSTREAM is
        # unreachable the honest answer is an error, not a fabricated success.
        return JSONResponse({"error": "upstream unreachable", "detail": str(e),
                             "rid": rid}, status_code=502)


def _safe_json(r: httpx.Response) -> Any:
    try:
        return r.json()
    except Exception:  # noqa: BLE001
        return {"__raw__": r.text[:4000]}
