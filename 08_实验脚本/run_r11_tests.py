"""Isolate global detector state between test files; keep every outcome."""
import json,os,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'07_修复验证/R11_unit_tests';OUT.mkdir(exist_ok=True)
results=[];total=0
for file in sorted((ROOT/'track2/tests').glob('test_*.py')):
    process=subprocess.run([sys.executable,str(file)],cwd=ROOT,env=dict(os.environ,PYTHONUTF8='1',PYTHONIOENCODING='utf-8',GUARD_R10='0'),capture_output=True,timeout=180)
    (OUT/(file.stem+'.log')).write_bytes(process.stdout+process.stderr)
    match=re.search(rb'Ran (\d+) tests?',process.stderr);count=int(match[1]) if match else 0;total+=count
    results.append({'file':file.name,'exit_code':process.returncode,'tests':count});print(file.name,process.returncode,count,flush=True)
(OUT/'verification.json').write_text(json.dumps({'checks':results,'tests':total},indent=2))
sys.exit(int(any(v['exit_code'] for v in results)))
