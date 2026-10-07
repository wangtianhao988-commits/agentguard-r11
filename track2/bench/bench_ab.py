"""Fixture-only same-PID control. Never imported by production deployment.

No HTTP control endpoint. Only the explicitly selected benchmark entrypoint installs
local OS signal callbacks. Target source and verifier remain unchanged.
"""
import asyncio
import json
import os
from pathlib import Path
import re
import signal
from starlette.responses import JSONResponse

if os.getenv('GUARD_LOCAL_FIXTURE_BENCHMARK') != '1':
    raise RuntimeError('This entrypoint requires explicit local fixture benchmark mode')
role = os.environ['BENCH_ROLE']
if role == 'native':
    import inprocess
    target = inprocess.app
    core = inprocess.core
elif role == 'framework':
    import gateway as core
    target = core.app
else:
    raise RuntimeError('Unknown benchmark role')
if core.GUARD.task_policies is not None:
    raise RuntimeError('Benchmark switching cannot disable task policies')

class Benchmark:
    mode = 'guard'
    period = 'initial'
    def transition(self):
        control = json.loads(Path('/evidence/bench_control.json').read_text(encoding='utf-8'))
        mode, period = control['mode'], control['period']
        if mode not in {'baseline', 'guard'} or not re.fullmatch(r'[a-zA-Z0-9_-]+', period):
            raise RuntimeError('Invalid local benchmark transition')
        directory = Path('/evidence')/period/('inline' if role == 'native' else 'framework')
        directory.mkdir(exist_ok=True, parents=True)
        core.STORE.rotate()
        core.STORE.dir = directory
        from rules import clear_cross_session_state
        with core.GUARD._lock:
            if os.getenv('GUARD_R8')=='1':
                os.environ['GUARD_GRAPH_STATE_PATH']='/state/'+period+'/r8.sqlite'
            if core.GUARD.r10:
                from runtime_r10 import R10Security
                core.GUARD.r10.close();core.GUARD.r10=R10Security()
                if core.GUARD.r10.intent:core.GUARD.r10.intent.reset()
                semantic=core.GUARD.r10.semantic
                if semantic:
                    semantic.cache.clear()
                    for key in semantic.stats:semantic.stats[key]=0
            core.GUARD._sessions.clear()
            clear_cross_session_state()
            for key in core.GUARD.stats:
                core.GUARD.stats[key] = 0
            core.GUARD.enabled = mode == 'guard'
        if role == 'native':
            inprocess._cpu_ns = 0
        self.mode, self.period = mode, period

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'lifespan':
            loop = asyncio.get_running_loop()
            # Event-loop callbacks avoid acquiring locks from an interrupted
            # signal handler while the evidence sweeper holds the same lock.
            loop.add_signal_handler(signal.SIGUSR1, self.transition)
            loop.add_signal_handler(signal.SIGUSR2, self.transition)
            return await target(scope, receive, send)
        if scope['type'] == 'http' and scope['path'] == ('/agentguard/health' if role == 'native' else '/health'):
            response = JSONResponse({'benchmark_only': True, 'role': role,
                'period': self.period, 'mode': self.mode, 'pid': os.getpid(),
                'guard': core.GUARD.snapshot(), 'records_dropped': core.STORE.dropped()})
            return await response(scope, receive, send)
        if role == 'native' and self.mode == 'baseline':
            # Same original application in the same PID, without ingress parsing,
            # detection or tool evidence. The transparent send hook sees no context
            # and invokes its original sender. Idle background cost is measured
            # separately and added conservatively to the paired increment.
            return await target.target(scope, receive, send)
        return await target(scope, receive, send)

app = Benchmark()
