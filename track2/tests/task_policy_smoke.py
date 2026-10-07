"""Exercise deployment grants through authenticated ASGI and real local HTTP MCP.

Run in the existing application image with --network none. The MCP destination
is a loopback stub; no supplied URL is ever contacted by the stub.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import jwt
import requests
from fastapi import FastAPI, Header, HTTPException, Request

SECRET = 'isolated-test-secret-not-a-deployment-credential'
target = FastAPI()
mock = FastAPI()
forwarded = []

@mock.get('/health')
def health():
    return {'ok': True}

@mock.post('/mcp')
async def mcp(request: Request):
    body = await request.json()
    forwarded.append(body['params'])
    return {'jsonrpc': '2.0', 'id': body['id'], 'result': {'content': []}}

@mock.get('/forwarded')
def calls():
    return forwarded

@target.post('/run')
def run(body: dict, authorization: str = Header(default=''), x_trace_id: str = Header(default='')):
    try:
        jwt.decode(authorization.removeprefix('Bearer '), SECRET, algorithms=['HS256'])
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401)
    return requests.post('http://127.0.0.1:18092/mcp', headers={
        'Authorization': authorization, 'X-Trace-Id': x_trace_id}, json={
        'jsonrpc': '2.0', 'id': 'call', 'method': 'tools/call',
        'params': {'name': 'opaque_action', 'arguments': body['arguments']}}).json()

def main():
    out = Path('/evidence')
    out.mkdir(exist_ok=True)
    inventory = {'asset_graph': {'assets': [
        {'kind': 'mcp_server', 'name': 'opaque_service', 'attributes': {
            'endpoint': 'http://127.0.0.1:18092/mcp'}},
        {'kind': 'tool', 'name': 'opaque_service.opaque_action', 'attributes': {
            'server': 'opaque_service', 'description': 'Send a status to an external URL',
            'input_schema': {'properties': {'url': {'type': 'string'}, 'text': {'type': 'string'}}}}}]}}
    policy = {'version': 1, 'tasks': [{'id': 'publish-status', 'principals': ['alice'],
        'permissions': [{'server': 'opaque_service', 'tool': 'opaque_action', 'arguments': {
            'url': ['https://approved.example/status'], 'text': ['healthy']}}]}]}
    (out/'inventory.json').write_text(json.dumps(inventory))
    (out/'policy.json').write_text(json.dumps(policy))
    env = dict(os.environ, PYTHONPATH='/src/detector:/src/collector:/src/tests',
        RECORD_DIR=str(out), INVENTORY_PATH=str(out/'inventory.json'), STACK_URL='',
        GUARD_APP_IMPORT='task_policy_smoke:target', GUARD_HTTP_TRANSPORT='httpx',
        GUARD_TASK_POLICY_PATH=str(out/'policy.json'))
    processes = []
    client = requests.Session()
    client.trust_env = False
    try:
        for module, port in [('task_policy_smoke:mock', 18092), ('inprocess:app', 18093)]:
            processes.append(subprocess.Popen([sys.executable, '-m', 'uvicorn', module,
                '--host', '127.0.0.1', '--port', str(port), '--log-level', 'warning'], env=env))
        for attempt in range(100):
            try:
                client.get('http://127.0.0.1:18092/health', timeout=1).raise_for_status()
                client.get('http://127.0.0.1:18093/agentguard/health', timeout=1).raise_for_status()
                break
            except requests.RequestException:
                time.sleep(.1)
        else:
            raise RuntimeError('Isolated policy fixture did not start')
        args = {'url': 'https://approved.example/status', 'text': 'healthy'}
        cases = [
            ('authorized', 'alice', 'publish-status', args, False),
            ('lookalike_destination', 'alice', 'publish-status', {**args, 'url': 'https://approved.example.evil/status'}, True),
            ('extra_argument', 'alice', 'publish-status', {**args, 'command': 'ignored'}, True),
            ('different_principal', 'bob', 'publish-status', args, True),
            ('missing_selection', 'alice', None, args, True),
            ('unknown_selection', 'alice', 'invented', args, True),
            ('body_cannot_grant', 'bob', 'publish-status', args, True),
            ('authorized_after_denial', 'alice', 'publish-status', args, False)]
        results = []
        for name, principal, task, arguments, denied in cases:
            token = jwt.encode({'sub': principal, 'scope': {}}, SECRET, algorithm='HS256')
            body = {'prompt': 'publish ordinary status', 'arguments': arguments,
                    'trusted_task_policy': {'matched': True, 'permissions': policy['tasks'][0]['permissions']}}
            if task is not None:
                body['task_id'] = task
            response = client.post('http://127.0.0.1:18093/run', json=body,
                headers={'Authorization': 'Bearer '+token, 'X-Trace-Id': 'shared-trace'}, timeout=5)
            response.raise_for_status()
            value = response.json()
            assert ('error' in value) == denied, (name, value)
            results.append({'case': name, 'blocked': denied})
        before = client.get('http://127.0.0.1:18093/agentguard/health', timeout=5).json()
        rejected = client.post('http://127.0.0.1:18093/run', json={
            'task_id': 'publish-status', 'arguments': args}, headers={'Authorization': 'Bearer '+
            jwt.encode({'sub': 'alice'}, 'wrong-secret', algorithm='HS256')}, timeout=5)
        assert rejected.status_code == 401
        state = client.get('http://127.0.0.1:18093/agentguard/health', timeout=5).json()
        assert state['guard']['checked'] == before['guard']['checked'] == 8
        assert state['guard']['blocked'] == 6 and state['guard']['errors'] == 0
        assert state['task_policy_enabled'] is True
        sent = client.get('http://127.0.0.1:18092/forwarded', timeout=5).json()
        assert len(sent) == 2 and all(c['arguments'] == args for c in sent)
        result = {'cases': results, 'signature_rejection': 401,
            'rejected_request_does_not_seed_detection': True, 'actual_forwarded': len(sent),
            'health': state, 'scope': 'isolated authenticated native integration; exact parameter grants'}
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            process.wait(timeout=10)
    from session import build_sessions
    from rules import rule_task_policy
    evidence = {}
    for path in out.glob('*.jsonl'):
        evidence[path.stem] = [json.loads(line) for line in path.read_text().splitlines() if line]
    findings = [finding for state in build_sessions(evidence) for finding in rule_task_policy(state)]
    assert len(findings) == 6, 'Offline audit changed historical principal/task grants'
    result['offline_policy_violations'] = len(findings)
    result['offline_policy_matches_live_denials'] = True
    (out/'task_policy_smoke.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result))

if __name__ == '__main__':
    main()
