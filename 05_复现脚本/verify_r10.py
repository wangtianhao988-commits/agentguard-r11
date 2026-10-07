"""R10 checks report failures; passing these checks does not assert all targets."""
import argparse,json,os,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--output-name',default='R10_final_review');p.add_argument('--live',action='store_true');a=p.parse_args()
assert Path(a.output_name).name==a.output_name
OUT=ROOT/'07_修复验证'/a.output_name;OUT.mkdir(exist_ok=False)
env=dict(os.environ,PYTHONUTF8='1',PYTHONIOENCODING='utf-8',GUARD_R9='1',GUARD_R8='1',GUARD_KG='1',GUARD_R10='0')
evidence=ROOT/'07_修复验证/R10_cpu_optimized/pair1_guard/evidence'
checks=[(f.stem,[str(f)]) for f in sorted((ROOT/'track2/tests').glob('test_*.py'))]
checks += [('external',['05_复现脚本/verify_external_r10.py']),
    ('official_runtime',['track2/eval/evaluate.py','--evidence',str(evidence),'--json',str(OUT/'runtime.json')]),
    ('official_enforcement',['track2/eval/eval_enforcement.py','--evidence',str(evidence),'--json',str(OUT/'enforcement.json')]),
    ('official_legacy_consistency',['track2/eval/consistency.py','--evidence',str(evidence)]),
    ('official_r10_audit',['track2/eval/r10_audit.py','--evidence',str(evidence),'--json',str(OUT/'audit.json')])]
if a.live:checks += [('deployment',['05_复现脚本/check_deployment.py','--output-name',a.output_name+'_live.json'])]
results=[];test_count=0
for name,arguments in checks:
    proc=subprocess.run([sys.executable,*arguments],cwd=ROOT,capture_output=True,env=env,timeout=180)
    (OUT/(name+'.log')).write_bytes(proc.stdout+proc.stderr)
    if name.startswith('test_'):
        match=re.search(rb'Ran (\d+) tests?',proc.stderr);test_count+=int(match[1]) if match else 0
    results.append({'name':name,'exit_code':proc.returncode});print(name,proc.returncode,flush=True)
(OUT/'verification.json').write_text(json.dumps({'checks':results,'tests':test_count},indent=2))
raise SystemExit(1 if any(r['exit_code'] for r in results) else 0)
