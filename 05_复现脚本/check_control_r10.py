"""Real native endpoint against official MCP; secrets/tokens are never saved."""
import json,sys,time
from pathlib import Path
import requests
ROOT=Path(__file__).resolve().parents[1];BASE='http://127.0.0.1:8100'
sys.path.insert(0,str(ROOT/'_scratch/competition/agentrange/scenario-runner'))
from token_readiness import wait_for_token
import httpx
def user(name):
    r=requests.post(BASE+'/login',json={'username':name},timeout=3);r.raise_for_status();body=r.json();token=body.get('access_token') or body.get('token')
    with httpx.Client() as client:wait_for_token(client,BASE,name,token)
    return {'Authorization':'Bearer '+token}
health=requests.get(BASE+'/agentguard/health',timeout=3).json()
assert health['trusted_control_plan_enabled']
out={'native_health_r10':health.get('r10') or health.get('guard',{}).get('r10'),'cases':[]}
cases=[('anonymous',{}, {'plan_id':'knowledge-reference','inputs':{'query':'CVE-2025-0001'}},401),
    ('approved-read',user('lwang'),{'plan_id':'knowledge-reference','inputs':{'query':'CVE-2025-0001'}},200),
    ('wrong-principal',user('lwang'),{'plan_id':'security-advisory','inputs':{'cve':'CVE-2025-0001'}},403),
    ('authorized-advisory',user('zsec'),{'plan_id':'security-advisory','inputs':{'cve':'CVE-2025-0001'}},200),
    ('forged-control',user('zsec'),{'plan_id':'security-advisory','inputs':{'cve':'CVE-2025-0001'},'steps':[{'tool':'exec'}]},403)]
for name,headers,body,expected in cases:
    started=time.perf_counter();r=requests.post(BASE+'/agentguard/execute',headers=headers,json=body,timeout=10)
    row={'name':name,'status':r.status_code,'expected':expected,'wall_ms':(time.perf_counter()-started)*1000}
    if r.status_code==200:
        answer=r.json();row.update(completed=answer['completed'],steps=len(answer['audit']),audit=answer['audit'])
        assert answer['completed'] and len(answer['audit'])==1
    out['cases'].append(row)
    assert r.status_code==expected,(name,r.status_code,r.text)
(ROOT/'07_修复验证/R10_control_http.json').write_text(json.dumps(out,indent=2))
print(json.dumps(out))
