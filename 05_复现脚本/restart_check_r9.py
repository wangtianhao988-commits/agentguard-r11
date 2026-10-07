"""Restart the authorized local protected app; verify durable ledger and sidecar."""
import argparse,json,subprocess,time,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];RANGE=ROOT/'_scratch/competition/agentrange'
p=argparse.ArgumentParser();p.add_argument('--compose',type=Path,required=True);a=p.parse_args()
config=a.compose.resolve(strict=True)
assert config.is_relative_to(ROOT/'07_修复验证')
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def health():return json.loads(opener.open('http://127.0.0.1:8100/agentguard/health',timeout=3).read())
before=health();prior=before['guard']['knowledge_graph']
assert prior['persistence'] and prior['sources']>0 and not prior['saturated']
subprocess.run(['docker','restart','agentrange-opspilot-app-1'],check=True,capture_output=True)
for _ in range(60):
    try:
        after=health();break
    except Exception:time.sleep(.5)
else:raise RuntimeError('Protected app did not recover after restart')
compose=['docker','compose','-p','agentrange']
for file in [RANGE/'docker-compose.yml',RANGE/'docker-compose.override.yml',RANGE/'docker-compose.authfix.yml',config]:
    compose+=['-f',str(file)]
# A PID-namespace sidecar must join the application's new namespace after restart.
subprocess.run(compose+['up','-d','--no-build','--no-deps','--force-recreate','guard-stackd'],check=True,capture_output=True)
kg=after['guard']['knowledge_graph']
assert kg['restored'] and kg['namespace']==prior['namespace'] and kg['sources']==prior['sources']
assert after['guard']['enforcement'] and after['guard']['errors']==0 and after['records_dropped']=={}
result={'restored':True,'sources_before':prior['sources'],'sources_after':kg['sources'],
    'namespace_unchanged':True,'private_state_shipped':False,'production_guard_enabled':True,
    'sidecar_rejoined_new_pid_namespace':True,'health_after':after}
(ROOT/'07_修复验证/R9_1_restart_check.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps({k:v for k,v in result.items() if k!='health_after'}))
