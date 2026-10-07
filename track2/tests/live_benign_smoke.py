"""Send one generated benign case through the repaired local competition range."""
import json
from pathlib import Path
import sys
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'_scratch/competition/agentrange/corpus-generator'))
from generate import generate

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def get(path):
    return json.loads(opener.open('http://127.0.0.1:8101'+path,timeout=15).read())
def post(path, data, headers=None):
    request = urllib.request.Request('http://127.0.0.1:8101'+path,
        data=json.dumps(data).encode(),headers=dict({'Content-Type':'application/json'},**(headers or {})))
    response = opener.open(request,timeout=20)
    return response.status,json.loads(response.read())

def main():
    event = next(e for e in generate() if not e.malicious)
    record = event.__dict__
    _, login = post('/login', {'username':event.actor['sub']})
    trace = 'review-benign-'+uuid.uuid4().hex[:12]
    before = get('/debug/guard')
    status, body = post('/run',{'model':'opspilot-stub','prompt':event.input['prompt']},
          {'Authorization':'Bearer '+login['access_token'], 'X-Trace-Id':trace, 'X-Instance-Id':event.instance_id})
    # The runner clears the stub's trajectory memory after a replay, so an idle
    # agent may legitimately make no tool calls. Probe a real read-only MCP tool
    # explicitly without registering/changing any stub trajectories.
    tool_status, tool_body = post('/mcp/knowledge',
        {'jsonrpc':'2.0','id':'review-safe','method':'tools/call',
         'params':{'name':'search','arguments':{'q':'onboarding'}}}, {'X-Trace-Id':trace})
    after = get('/debug/guard')
    result = {'http_status':status,'tool_http_status':tool_status,
              'trace':trace,'scenario':event.scenario,
              'scope':'agent HTTP availability and explicit read-only MCP call; not a full corpus replay',
              'health':get('/health'), 'delta':{k:after[k]-before[k]
              for k in ('checked','blocked','alerted','allowed','errors')}}
    print(json.dumps(result))
    assert status == 200 and tool_status == 200 and 'result' in tool_body
    assert result['delta']['checked'] > 0
    assert result['delta']['blocked'] == result['delta']['errors'] == 0
    (ROOT/'07_修复验证/live_benign_smoke.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result))

if __name__ == '__main__':
    main()
