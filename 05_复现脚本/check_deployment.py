"""Read-only/inert probes of the R3 native entry and authentication boundary."""
import json
import argparse
import sys
import httpx
from pathlib import Path
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def request(port, path, body=None, headers=None):
    raw = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(f'http://127.0.0.1:{port}{path}', data=raw,
        headers={'Content-Type': 'application/json', **(headers or {})})
    try:
        response = opener.open(req, timeout=3)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, json.loads(response.read())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-name', default='R4_deployment_check.json')
    args = parser.parse_args()
    if Path(args.output_name).name != args.output_name:
        raise ValueError('output-name must be a file name')
    status, health = request(8100, '/agentguard/health')
    assert status == 200 and health['integration'] == 'inprocess'
    assert health['guard']['enforcement'] and health['guard']['fail_closed']
    assert health['tool_profile_loaded'] > 0 and not health.get('benchmark_only')
    kg = health['guard']['knowledge_graph']
    assert kg['enabled'] and not kg['saturated'] and kg['observation_errors'] == 0
    assert kg.get('version')=='R8' and kg['persistence'] and not kg['expired']
    assert set(kg['features'])=={'joint','multi_hop','persistence','planner','isolation'}
    checked = health['guard']['checked']
    status, _ = request(8100, '/me')
    assert status == 401
    status, _ = request(8100, '/run', {'prompt': 'inert boundary probe'},
                         {'Authorization': 'Bearer invalid.payload.signature', 'X-Trace-Id': 'auth-boundary-probe'})
    assert status == 401
    _, after = request(8100, '/agentguard/health')
    assert after['guard']['checked'] == checked
    closed = {}
    for path in ['/login', '/run', '/v1/chat/completions', '/mcp/customer-db']:
        status, _ = request(8101, path, {})
        assert status == 404
        closed[path] = status
    status, login = request(8100, '/login', {'username': 'lwang'})
    assert status == 200
    token = login.get('access_token') or login.get('token')
    assert token
    sys.path.insert(0, str(ROOT/'_scratch/competition/agentrange/scenario-runner'))
    from token_readiness import wait_for_token
    with httpx.Client(trust_env=False) as client:
        wait_for_token(client, 'http://127.0.0.1:8100', 'lwang', token)
    status, _ = request(8100, '/me', headers={'Authorization': 'Bearer ' + token})
    assert status == 200
    result = {'mode': 'inprocess', 'health': True, 'unauthenticated_me': 401,
              'production_enforcement_enabled': True, 'benchmark_switch_absent': True,
              'knowledge_graph_enabled': True, 'knowledge_graph_saturated': False,
              'version':'R8','features':kg['features'],'persistence':True,'restored':kg['restored'],
              'invalid_token_run': 401, 'invalid_request_added_tool_checks': 0,
              'closed_parallel_gateway_routes': closed, 'valid_user_me': 200,
              'tokens_retained_in_result': False}
    (ROOT/'07_修复验证'/args.output_name).write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result))

if __name__ == '__main__':
    main()
