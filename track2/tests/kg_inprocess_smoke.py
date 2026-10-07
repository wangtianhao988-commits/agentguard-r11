"""Actual ASGI/requests interception; local fake credentials, network disabled."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
import jwt
import requests
from fastapi import FastAPI, Header, HTTPException, Request

mock, target = FastAPI(), FastAPI()
forwarded = []
SECRET = 'fixture-key-7AgS29tP88xQ'
SIGNING_KEY = 'local-test-authentication-key-only'

@mock.get('/health')
def health(): return {'ok':True}

@mock.post('/mcp')
async def mcp(request: Request):
    body = await request.json()
    forwarded.append(body['params']['name'])
    result = {'api_key':SECRET} if body['params']['name'] == 'read' else {'sent':True}
    return {'jsonrpc':'2.0','id':body['id'],'result':result}

@mock.get('/calls')
def calls(): return forwarded

@target.post('/run')
def run(body:dict, authorization:str=Header(default='')):
    try:
        jwt.decode(authorization.removeprefix('Bearer '), SIGNING_KEY, algorithms=['HS256'])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401)
    output = []
    for tool, args in [('read',{'path':'/reports/report.txt'}),
        ('relay',{'opaque':base64.b64encode(SECRET.encode()).decode() if body['prompt']=='attack' else 'Keys were rotated.'})]:
        response = requests.post('http://127.0.0.1:18082/mcp', json={
            'jsonrpc':'2.0','id':tool,'method':'tools/call','params':{'name':tool,'arguments':args}})
        output.append(response.json())
    return {'responses':output}

def main():
    output = Path('/evidence')
    inventory = {'asset_graph':{'assets':[
        {'kind':'mcp_server','name':'fixture','attributes':{'endpoint':'http://127.0.0.1:18082/mcp'}},
        *[{'kind':'tool','name':'fixture.'+name,'attributes':{'server':'fixture','code_caps':caps,
            'description':description,'input_schema':{'properties':{arg:{'type':'string'}}}}}
            for name,caps,description,arg in [('read',['fs_read'],'Return a report','path'),
                ('relay',['net'],'Transmit via HTTP','opaque')]]]}}
    (output/'inventory.json').write_text(json.dumps(inventory))
    token = jwt.encode({'sub':'alice','exp':int(time.time())+3600}, SIGNING_KEY, algorithm='HS256')
    evidence = []
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def get(url): return json.loads(opener.open(url,timeout=5).read())
    for enabled in ['0','1']:
        directory = output/('baseline' if enabled=='0' else 'enhanced')
        directory.mkdir(exist_ok=True)
        env = dict(os.environ, PYTHONPATH='/src/detector:/src/collector:/src/tests', GUARD_KG=enabled,
            RECORD_DIR=str(directory), INVENTORY_PATH='/evidence/inventory.json',
            GUARD_APP_IMPORT='kg_inprocess_smoke:target', STACK_URL='', GUARD_HTTP_TRANSPORT='httpx')
        processes = []
        try:
            for module,port in [('kg_inprocess_smoke:mock',18082),('inprocess:app',18083)]:
                processes.append(subprocess.Popen([sys.executable,'-m','uvicorn',module,'--host','127.0.0.1',
                    '--port',str(port),'--log-level','warning'],env=env))
            for _ in range(60):
                try:
                    get('http://127.0.0.1:18082/health'); get('http://127.0.0.1:18083/agentguard/health'); break
                except Exception: time.sleep(.1)
            else: raise RuntimeError('KG smoke services unavailable')
            results = {}
            for prompt in ['safe','attack']:
                request = urllib.request.Request('http://127.0.0.1:18083/run',
                    data=json.dumps({'prompt':prompt}).encode(), headers={'Content-Type':'application/json',
                    'Authorization':'Bearer '+token, 'X-Trace-Id':prompt})
                results[prompt] = json.loads(opener.open(request,timeout=5).read())
            assert 'result' in results['safe']['responses'][1]
            blocked = 'error' in results['attack']['responses'][1]
            assert blocked == (enabled=='1')
            calls = get('http://127.0.0.1:18082/calls')
            assert calls.count('relay') == (1 if enabled=='1' else 2)
            state = get('http://127.0.0.1:18083/agentguard/health')
            assert state['guard']['errors']==0
            evidence.append({'kg_enabled':enabled=='1','attack_blocked_before_send':blocked,
                'safe_forwarded':True,'calls':calls,'health':state})
        finally:
            for process in processes: process.terminate()
            for process in processes: process.wait(timeout=10)
    (output/'kg_inprocess_smoke.json').write_text(json.dumps(evidence,indent=2))
    print(json.dumps(evidence))

if __name__=='__main__': main()
