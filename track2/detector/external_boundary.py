"""Check bound external returns with the existing, unchanged R11 verifier.

The collector supplies trusted task and exact call binding. This module never
reads archive labels or gives returned text authority to change the task.
"""
import hashlib
import itertools
import json
import os
import threading
import time

_ORDINALS = itertools.count(1)
_LOG_LOCK = threading.Lock()


class ExternalBoundary:
    def __init__(self, verifier):
        if verifier is None:
            raise ValueError('External boundary requires existing R11 verifier')
        self.verifier = verifier
        self.ordinal = next(_ORDINALS)
        self.log_path = os.environ.get('GUARD_R12_AUDIT_PATH')

    def inspect(self, prompt, call, call_id, body):
        from session import _unwrap_tool_result
        value = _unwrap_tool_result(body)
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
        started = time.perf_counter_ns()
        before = self.verifier.stats.get('errors', 0)
        event = {'guard_ordinal': self.ordinal, 'call_id': call_id,
                 'source_trust': 'EXTERNAL_DATA', 'tool': call.server + '.' + call.tool,
                 'arguments': call.arguments, 'trusted_user_goal': prompt,
                 'returned_text_sha256': hashlib.sha256(text.encode()).hexdigest(),
                 'returned_text': text, 'authorization_source': 'original user task'}
        try:
            verdict = self.verifier.judge_return(prompt, text)
            if type(verdict.get('malicious')) is not bool:
                raise ValueError('Boundary verdict schema mismatch')
            event.update(block=verdict['malicious'], boundary_violation=verdict['malicious'],
                         verifier=verdict, error=None)
        except Exception as error:
            # Budget failures outside the HTTP helper must also invalidate TP.
            if self.verifier.stats.get('errors', 0) == before:
                self.verifier.stats['errors'] = before + 1
            event.update(block=True, boundary_violation=None, error=type(error).__name__)
        event['latency_us'] = (time.perf_counter_ns() - started) / 1000
        if self.log_path:
            with _LOG_LOCK:
                with open(self.log_path, 'a', encoding='utf-8') as stream:
                    stream.write(json.dumps(event, ensure_ascii=False) + '\n')
        return event
