"""Authenticated real official-tool/model execution; never print/store JWTs."""
import argparse,json,time
from pathlib import Path
import requests
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser();parser.add_argument('--output-name',default='R11_model_native_current');args=parser.parse_args()
if Path(args.output_name).name!=args.output_name:raise ValueError('Output must be a directory name')
directory=ROOT/'07_修复验证'/args.output_name;directory.mkdir(parents=True,exist_ok=False)
output=directory/'model_http_checks.json'
cases=[]
for principal,body in [('lwang',{'plan_id':'knowledge-reference','inputs':{'query':'release checklist'}}),
                       ('zsec',{'plan_id':'security-advisory','inputs':{'cve':'CVE-2025-0001'}}),
                       ('lwang',{'plan_id':'security-advisory','inputs':{'cve':'CVE-2025-0001'}}),
                       ('zsec',{'plan_id':'security-advisory','inputs':{'cve':'CVE-2025-9999'}})]:
    response=requests.post('http://127.0.0.1:8100/login',json={'username':principal},timeout=5);response.raise_for_status()
    token=response.json()['access_token']
    started=time.perf_counter()
    response=requests.post('http://127.0.0.1:8100/agentguard/execute-model',headers={'Authorization':'Bearer '+token},json=body,timeout=90)
    cases.append({'principal':principal,'request':body,'http_status':response.status_code,'wall_ms':(time.perf_counter()-started)*1000,'response':response.json()})
    print(principal,body['plan_id'],response.status_code,flush=True)
response=requests.post('http://127.0.0.1:8100/agentguard/execute-model',json={'plan_id':'knowledge-reference','inputs':{'query':'checklist'}},timeout=5)
cases.append({'principal':None,'http_status':response.status_code})
assert [v['http_status'] for v in cases]==[200,200,403,403,401]
assert all(v['response']['completed'] for v in cases[:2])
output.write_text(json.dumps({'cases':cases,'actual_model':True,'actual_official_tools':True},ensure_ascii=False,indent=2),encoding='utf-8')
print('All 5 native HTTP model-mode checks passed',flush=True)
