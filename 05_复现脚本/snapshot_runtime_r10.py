"""Attest deployed extension assets, separately from official asset ground truth."""
import hashlib,json,subprocess
from pathlib import Path
import requests
ROOT=Path(__file__).resolve().parents[1]
from attest_official_runtime import attest
health=requests.get('http://127.0.0.1:8100/agentguard/health',timeout=3).json()
assert not health.get('benchmark_only') and health['guard']['enforcement'] and health['trusted_control_plan_enabled']
assert health['guard']['r10']['semantic']['head_sha256']==json.loads((ROOT/'track2/models/r10/head.json').read_text())['head_parameters_sha256']
code='import hashlib,json,pathlib,onnxruntime,tokenizers,numpy; print(json.dumps({"onnxruntime":onnxruntime.__version__,"tokenizers":tokenizers.__version__,"numpy":numpy.__version__,"files":{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for d in ["/src/collector","/src/detector","/src/models/r10"] for p in pathlib.Path(d).glob("*") if p.is_file()}}))'
actual=json.loads(subprocess.run(['docker','exec','agentrange-opspilot-app-1','python','-c',code],check=True,capture_output=True,text=True).stdout)
for path,sha in actual['files'].items():
    rel=path.removeprefix('/src/');assert hashlib.sha256((ROOT/'track2'/rel).read_bytes()).hexdigest()==sha
result={'official_source_attestation':attest(),'production_health':health,'runtime_assets':actual,
    'extension_asset_graph':{'nodes':[{'id':'native','kind':'AgentGuardIntegration'},
        {'id':'encoder','kind':'model','name':'MiniLM-L3 quantized ONNX','sha256':health['guard']['r10']['semantic']['encoder_sha256']},
        {'id':'head','kind':'model','name':'R10 learned linear head','sha256':health['guard']['r10']['semantic']['head_sha256']},
        {'id':'onnxruntime','kind':'inference_framework','version':actual['onnxruntime']},
        {'id':'fixed-plan','kind':'authorization_policy','enabled':health['trusted_control_plan_enabled']}],
        'edges':[{'src':'native','rel':'loads','dst':'encoder'},{'src':'native','rel':'loads','dst':'head'},
            {'src':'encoder','rel':'executed_by','dst':'onnxruntime'},{'src':'native','rel':'enforces','dst':'fixed-plan'}]},
    'scope':'Extension components separately identified, not added to official asset ground-truth denominator'}
(ROOT/'07_修复验证/R10_runtime_snapshot.json').write_text(json.dumps(result,indent=2));print(json.dumps({'extension_assets':5,'official_app_source_matches':result['official_source_attestation']['agentrange-opspilot-app-1']['files_matched'],'r10_loaded':True}))
