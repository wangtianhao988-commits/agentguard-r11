"""Inline enforcement: turn a finding into a refused tool call.

What was missing
----------------
Everything measured so far ran the detector **offline** over collected evidence. The
gateway forwarded every request and recorded what happened. That is detection and
audit, which is two thirds of the brief's "实现检测、阻断与审计" -- the middle word had
no implementation at all.

What this adds
--------------
Per-instance session state that is built up **as the calls arrive**, evaluated before
each call is forwarded, and acted on:

    ALLOW  -> forward, record
    ALERT  -> forward, record the alert (the brief permits "阻断攻击链路**或告警**")
    BLOCK  -> do NOT forward; return a JSON-RPC error to the agent, record the
              decision and its rationale

Design constraints, all from the brief
--------------------------------------
* **业务 0 中断.** A blocked call must not break the session: the agent receives a
  tool error, which every agent loop already handles, rather than an exception or a
  hang. And with a measured false-positive rate of zero over the benign corpus, the
  enforcement path is not expected to fire on ordinary work at all.
* **响应时间 < 1 秒.** The rules run inline. They are the same rules measured at
  ~1 ms per request; the enforcement adds a decision, not a second analysis.
* **可审计.** Every decision records which rule fired, on what evidence, and what was
  refused -- so a block can be argued with after the fact rather than taken on faith.

Enforcement points
------------------
    C  agent -> MCP        refuse the individual tool call
    E  driver -> framework refuse the request to the vulnerable endpoint

Deliberately NOT enforced at A (`/run`). Blocking an entire session because one
finding appeared would break the business requirement far more often than it would
stop an attack, and the finding is about a tool call, not about the user's request.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# The detector is imported, never forked. A second copy of the rules would drift and
# the drift would be invisible -- the same failure this project has already paid for
# three times with duplicated definitions and duplicated vocabularies.
#
# The path is searched rather than computed: in the repo the detector is a sibling
# package (`track2/detector/`), in the image both are flattened into `/app` with the
# detector under `/app/detector/`. Hardcoding `parents[1]` worked in the repo and
# silently failed in the image, which is how this kind of assumption always breaks.
_HERE = Path(__file__).resolve().parent
for _cand in (_HERE / "detector", _HERE.parent / "detector", _HERE, _HERE.parent):
    if (_cand / "rules.py").exists() and str(_cand) not in sys.path:
        sys.path.insert(0, str(_cand))

ALLOW, ALERT, BLOCK = "ALLOW", "ALERT", "BLOCK"


@dataclass
class Decision:
    action: str
    session_id: str
    findings: List[Any] = field(default_factory=list)
    reason: str = ""
    latency_us: float = 0.0

    @property
    def blocked(self) -> bool:
        return self.action == BLOCK

    def to_json(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "session_id": self.session_id,
            "reason": self.reason,
            "latency_us": round(self.latency_us, 1),
            "findings": [f.to_json() for f in self.findings],
        }


class InlineGuard:
    """Session state built as calls arrive, evaluated before each call is forwarded."""

    def __init__(self, max_sessions: int = 4096,
                 block_severities: tuple = ("BLOCK",),
                 enabled: bool = True, task_policies=None, fail_closed: bool = True) -> None:
        self._sessions: Dict[str, Any] = {}
        if max_sessions < 1:
            raise ValueError("max_sessions must be positive")
        self._lock = threading.RLock()
        self._max = max_sessions
        self._block_sev = set(block_severities)
        self.enabled = enabled
        self.task_policies = task_policies
        self.fail_closed = fail_closed
        self.r10 = None
        if __import__('os').environ.get('GUARD_R10') == '1':
            from runtime_r10 import R10Security
            self.r10=R10Security()
        self.stats = {"checked": 0, "blocked": 0, "alerted": 0, "allowed": 0,
                      "errors": 0, "total_us": 0.0}

    # -- state ----------------------------------------------------------

    def _session(self, sid: str):
        from session import Session
        s = self._sessions.get(sid)
        if s is None:
            # Bounded: an unbounded per-session map is a memory leak on a long run,
            # and a guard that leaks is a guard that gets disabled in production.
            if len(self._sessions) >= self._max:
                for k in list(self._sessions)[: max(1, self._max // 8)]:
                    self._sessions.pop(k, None)
            s = Session(instance_id=sid)
            if self.task_policies is not None:
                # Eviction or a missing authenticated observation cannot turn a
                # mandatory deployment policy back into optional enforcement.
                s.trusted_task_policy = self.task_policies.bind(None, None)
            self._sessions[sid] = s
        return s

    def observe_run(self, sid: str, headers: Dict[str, str], body: Dict[str, Any]) -> None:
        """Record the `/run` context so later tool calls can be judged against it."""
        import base64
        with self._lock:
            s = self._session(sid)
            s.prompt = (body or {}).get("prompt", "") or s.prompt
            s.skill = (body or {}).get("skill") or s.skill
            auth = (headers or {}).get("authorization", "")
            if auth.startswith("Bearer ") and not s.identity:
                try:
                    part = auth.split(" ", 1)[1].split(".")[1]
                    part += "=" * (-len(part) % 4)
                    s.identity = json.loads(base64.urlsafe_b64decode(part))
                except (ValueError, IndexError, TypeError):
                    pass
            if self.task_policies is not None:
                selection = (headers or {}).get('x-guard-task') or (body or {}).get('task_id')
                s.trusted_task_policy = self.task_policies.bind(s.identity.get('sub'), selection)

    def policy_binding(self, sid):
        with self._lock:
            state = self._sessions.get(sid)
            return state.trusted_task_policy if state is not None else None

    def observe_skill_catalog(self, sid: str, messages: List[Dict[str, Any]]) -> None:
        """Capture the skill catalog so `undeclared-skill-capability` can run."""
        from session import _skill_catalog_from, _SKILL_CATALOG
        with self._lock:
            s = self._session(sid)
            s.messages = list(messages or [])
            if not s.skill_catalog:
                s.skill_catalog = _skill_catalog_from(messages or []) or list(_SKILL_CATALOG)

    def observe_tool_result(self, sid: str, call_id: str, body: Any,
                            ok: bool = True) -> None:
        """Join a returned value to its exact request, including concurrent calls.

        Offline reconstruction already did this. The live guard must also see the
        returned text before judging the next action, otherwise memory poisoning
        and content-flow checks silently use different inputs in the two paths.
        """
        from session import _unwrap_tool_result
        with self._lock:
            s = self._sessions.get(sid)
            if s is None:
                return body,None
            for index in range(len(s.calls)-1, -1, -1):
                call = s.calls[index]
                if getattr(call, "_guard_call_id", None) == call_id:
                    from rules import observe_knowledge_result,knowledge_engine
                    delivered,audit=body,None
                    engine=knowledge_engine()
                    if self.enabled and ok and hasattr(engine,'project_result'):
                        delivered,audit=engine.project_result(call,body)
                    if self.enabled and ok and __import__('os').environ.get('GUARD_R9','1') != '0':
                        from generalization import injection_evidence
                        suspicious = injection_evidence(_unwrap_tool_result(body))
                        if suspicious and hasattr(engine,'policy'):
                            # External authority claims cannot alter the original task.
                            # Use the existing auditable deny-result intervention.
                            delivered,audit=engine.policy._deny(body,'external result impersonates trusted instructions')
                            audit['r9_trust_boundary']=suspicious
                    if self.enabled and ok and audit is None and self.r10:
                        semantic=self.r10.inspect_result(body,s)
                        if semantic and semantic['block'] and hasattr(engine,'policy'):
                            delivered,audit=engine.policy._deny(body,'learned semantic injection score exceeds frozen threshold')
                            audit['r10_semantic']=semantic
                    if audit is not None:
                        from rules import result_intervention_finding
                        call._r8_raw_response=body
                        audit['finding']=result_intervention_finding(s,index,audit).to_json()
                    call.result = _unwrap_tool_result(delivered)
                    call.ok = ok and not (isinstance(delivered, dict) and "error" in delivered)
                    try:
                        observe_knowledge_result(s, index)
                        if self.r10:self.r10.observe(s,call)
                    except Exception as error:
                        # Do not deliver a new source that failed durable commit.
                        # Restart can then safely recover the last committed state.
                        if not hasattr(engine,'project_result'): raise
                        engine.saturated=True
                        self.stats['errors']+=1
                        delivered,audit=engine.policy._deny(body,'provenance commit failed: '+type(error).__name__)
                        call.ok=False;call.result=_unwrap_tool_result(delivered);call._r8_raw_response=body
                        from rules import result_intervention_finding
                        audit['finding']=result_intervention_finding(s,index,audit).to_json()
                    call._r8_result_audit = None if audit is None else {k:v for k,v in audit.items() if k != 'finding'}
                    return delivered,audit
            return body,None

    def remember(self, sid: str) -> None:
        """Hand the finished session to the cross-session state."""
        from rules import remember_session
        with self._lock:
            s = self._sessions.get(sid)
            if s is not None:
                remember_session(s)

    # -- evaluation -----------------------------------------------------

    def _invalid_decision(self, sid, started, reason, error=False):
        """Reject only the unjudgeable call; retain visible health counters."""
        action = BLOCK if self.fail_closed or self.task_policies is not None else ALERT
        elapsed = (time.perf_counter()-started)*1e6
        with self._lock:
            self.stats['checked'] += 1
            self.stats['total_us'] += elapsed
            self.stats['blocked' if action == BLOCK else 'alerted'] += 1
            self.stats['errors'] += int(error)
        return Decision(action, sid, reason=reason, latency_us=elapsed)

    def check_tool_call(self, sid: str, server: str, tool: str,
                        arguments: Dict[str, Any], call_id: str = "") -> Decision:
        """Judge a tool call BEFORE it is forwarded."""
        if not self.enabled:
            return Decision(ALLOW, sid, reason="enforcement disabled")

        t0 = time.perf_counter()
        if not isinstance(arguments, dict):
            return self._invalid_decision(sid, t0, 'invalid tool arguments: expected a JSON object')
        try:
            from rules import analyse_session
            from session import ToolCall
            with self._lock:
                s = self._session(sid)
                if getattr(s,'_r8_aborted',False):
                    return self._invalid_decision(sid,t0,'R8 task suspended by intervention plan')
                call = ToolCall(server=server, tool=tool, arguments=arguments or {})
                call.trusted_task_policy = s.trusted_task_policy
                call._guard_call_id = call_id
                s.calls.append(call)
                all_findings = analyse_session(s)
                if self.r10:all_findings += self.r10.findings(s,evaluate_intent=not any(f.severity=='BLOCK' for f in all_findings))
                broken = [f for f in all_findings if f.rule_id.endswith(":error")]
                if broken:
                    raise RuntimeError("; ".join(f.summary for f in broken))
                findings = [f for f in all_findings
                            if getattr(f, "severity", "") in ("BLOCK", "ALERT")
                            and (f.rule_id not in {'task-policy-violation', 'kg-sensitive-flow', 'kg-authorization', 'kg-state-budget'}
                                 and not f.rule_id.startswith(('r8-', 'r9-', 'r10-'))
                                 or f.evidence.get('call_index') == len(s.calls)-1)]
                if any('abort-task' in f.evidence.get('intervention',{}).get('selected',[]) for f in findings):
                    s._r8_aborted=True
                # Keep rule state changes inside the same critical section.
                self.remember(sid)
        except Exception as e:  # noqa: BLE001
            return self._invalid_decision(sid, t0,
                f'guard error: {type(e).__name__}: {e}', error=True)

        latency_us = (time.perf_counter() - t0) * 1e6
        blocking = [f for f in findings if f.severity in self._block_sev]
        action = BLOCK if blocking else (ALERT if findings else ALLOW)
        reason = ""
        if blocking:
            f = blocking[0]
            reason = f"{f.rule_id}: {f.summary}"
        elif findings:
            reason = f"{findings[0].rule_id} (alert only): {findings[0].summary}"

        # Keep the cross-session state current. WITHOUT THIS the
        # `cross-session-read-then-egress` rule is DEAD in the live path while passing
        # its offline test: the guard defined `remember()` and never called it, so the
        # per-principal read history stayed empty and the rule could not fire. The
        # offline evaluator called `remember_session` itself, so both paths reported
        # 100% while only one of them actually had that rule.
        with self._lock:
            self.stats["checked"] += 1
            self.stats["total_us"] += latency_us
            self.stats[{"BLOCK": "blocked", "ALERT": "alerted",
                        "ALLOW": "allowed"}[action]] += 1
        return Decision(action, sid, findings=findings, reason=reason, latency_us=latency_us)

    def check_framework_call(self, method: str, path: str, query: Dict[str, Any],
                             body: Any, raw_head: str) -> Decision:
        """Judge a framework request before it is forwarded."""
        if not self.enabled:
            return Decision(ALLOW, f"E:{path}", reason="enforcement disabled")
        t0 = time.perf_counter()
        try:
            from rules import rule_framework_calls
            row = {"rid": f"inline-{int(time.time()*1000)}", "path": f"/langflow/{path}",
                   "method": method, "query": query, "body": body,
                   "content_type": "", "multipart_fields": {}}
            for token in ("filename=", "name="):
                i = raw_head.find(token)
                if i >= 0:
                    row["multipart_fields"][token.rstrip("=")] = \
                        raw_head[i + len(token):].split("\r\n")[0].strip('"')
            findings = [f for f in rule_framework_calls([row])
                        if getattr(f, "severity", "") in ("BLOCK", "ALERT")]
        except Exception as e:  # noqa: BLE001
            return self._invalid_decision(f'E:{path}', t0,
                f'guard error: {type(e).__name__}: {e}', error=True)

        latency_us = (time.perf_counter() - t0) * 1e6
        blocking = [f for f in findings if f.severity in self._block_sev]
        action = BLOCK if blocking else (ALERT if findings else ALLOW)
        with self._lock:
            self.stats["checked"] += 1
            self.stats["total_us"] += latency_us
            self.stats[{"BLOCK": "blocked", "ALERT": "alerted",
                        "ALLOW": "allowed"}[action]] += 1
        return Decision(action, f"E:{path}", findings=findings,
                        reason=(blocking[0].summary if blocking else
                                (findings[0].summary if findings else "")),
                        latency_us=latency_us)

    def snapshot(self, reset: bool = False) -> Dict[str, Any]:
        with self._lock:
            st = dict(self.stats)
            if reset:
                for k in self.stats:
                    self.stats[k] = 0
        st["mean_us"] = round(st["total_us"] / max(st["checked"], 1), 1)
        st["total_us"] = round(st["total_us"], 1)
        st["enforcement"] = self.enabled
        st['fail_closed'] = self.fail_closed
        st["block_severities"] = sorted(self._block_sev)
        from rules import knowledge_engine
        kg = knowledge_engine()
        st['knowledge_graph'] = {'enabled': kg is not None, **(dict(kg.stats, sources=len(kg.sources),
            artifacts=len(kg.artifacts), saturated=kg.saturated) if kg else {})}
        if hasattr(kg,'features'):
            st['knowledge_graph'].update(version='R8',features=sorted(kg.features),
                persistence=kg.db is not None,restored=kg.restored,expired=kg.expired,namespace=kg.namespace)
        if self.r10:st['r10']=self.r10.snapshot()
        return st

    def close(self):
        if self.r10:self.r10.close()
