"""Measure client-visible response times on real local attack and benign paths."""
import copy
import json
import os
from pathlib import Path
import sys
import time
import uuid
import argparse

ROOT = Path(__file__).resolve().parents[1]
RANGE = ROOT / '_scratch/competition/agentrange'
sys.path[:0] = [str(RANGE / 'scenario-runner'), str(RANGE / 'corpus-generator'), str(RANGE / 'attack')]
for key in list(os.environ):
    if key.lower() in {'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'}:
        os.environ.pop(key)
os.environ.update(OPSPILOT_BASE='http://127.0.0.1:8101',
                  LANGFLOW_BASE='http://127.0.0.1:8101/langflow', LLM_STUB_BASE='http://127.0.0.1:8000')
import runner
from generate import generate, public_record, trajectory_map
import httpx

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['gateway', 'inprocess'], default='gateway')
    parser.add_argument('--output-name', default='client_response.json')
    args = parser.parse_args()
    if Path(args.output_name).name != args.output_name:
        raise ValueError('output-name must be a file name')
    runner.OPSPILOT = 'http://127.0.0.1:8100' if args.mode == 'inprocess' else 'http://127.0.0.1:8101'
    events = generate()
    selected = copy.deepcopy([e for e in events if e.malicious] + [e for e in events if not e.malicious][:160])
    prefix = 'latency-' + uuid.uuid4().hex[:8] + '-'
    for event in selected:
        event.instance_id = prefix + event.instance_id
    truth = {e.instance_id: e.malicious for e in selected}
    rows = []
    base = httpx.Client
    class MeasuredClient(base):
        def send(self, request, *args, **kwargs):
            started = time.perf_counter()
            response = super().send(request, *args, **kwargs)
            if request.url.path == '/run' or (request.url.path.startswith('/langflow/') and not request.url.path.endswith('/auto_login')):
                rows.append({'ms': (time.perf_counter() - started) * 1000,
                    'status': response.status_code,
                    'malicious': truth.get(request.headers.get('x-instance-id'), True),
                    'path': request.url.path,
                    'framework_block_header': bool(response.headers.get('x-guard-blocked'))})
            return response
    try:
        httpx.Client = MeasuredClient
        runner.inject_trajectories(trajectory_map(selected))
        runner.replay_events([public_record(e) for e in selected])
    finally:
        runner.clear_trajectories()
        httpx.Client = base
    def stats(values):
        values = sorted(values)
        return {'n': len(values), 'p99_ms': values[int(.99 * len(values))], 'max_ms': max(values)}
    result = {'scope': 'driver HTTP elapsed time, includes agent/tool/upstream and stack capture; fixed templates',
              'attack': stats([r['ms'] for r in rows if r['malicious']]),
              'benign': stats([r['ms'] for r in rows if not r['malicious']]),
              'http_errors': sum(r['status'] >= 400 for r in rows), 'requests': rows}
    assert len(rows) == 240
    assert result['http_errors'] == 0
    result['integration'] = args.mode
    (ROOT / '07_修复验证' / args.output_name).write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k != 'requests'}))

if __name__ == '__main__':
    main()
