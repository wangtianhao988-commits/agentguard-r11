"""Final R9.1 review: isolated tests, frozen external traces, official evidence."""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--output-name',default='R9_1_final_review');p.add_argument('--live',action='store_true');a=p.parse_args()
assert Path(a.output_name).name==a.output_name
OUT=ROOT/'07_修复验证'/a.output_name
OUT.mkdir(exist_ok=False)
env=dict(os.environ,PYTHONUTF8='1',PYTHONIOENCODING='utf-8',GUARD_R9='1',GUARD_R8='1',GUARD_KG='1')
evidence=ROOT/'07_修复验证/R9_1_cpu_verified/pair1_guard/evidence'
checks=[(f.stem,[str(f)]) for f in sorted((ROOT/'track2/tests').glob('test_*.py'))]
checks += [('external',['05_复现脚本/verify_generalization_r9.py']),
    ('official_runtime',['track2/eval/evaluate.py','--evidence',str(evidence),'--json',str(OUT/'runtime.json')]),
    ('official_enforcement',['track2/eval/eval_enforcement.py','--evidence',str(evidence),'--json',str(OUT/'enforcement.json')]),
    ('official_consistency',['track2/eval/consistency.py','--evidence',str(evidence)]),
    ('official_audit',['track2/eval/r9_audit.py','--evidence',str(evidence),'--json',str(OUT/'audit.json')])]
if a.live:checks += [('deployment',['05_复现脚本/check_deployment.py','--output-name',a.output_name+'_live.json'])]
results=[]
for name,args in checks:
    proc=subprocess.run([sys.executable,*args],cwd=ROOT,capture_output=True,env=env,timeout=120)
    (OUT/(name+'.log')).write_bytes(proc.stdout+proc.stderr)
    results.append({'name':name,'exit_code':proc.returncode});print(name,proc.returncode,flush=True)
(OUT/'verification.json').write_text(json.dumps(results,indent=2))
raise SystemExit(1 if any(r['exit_code'] for r in results) else 0)
