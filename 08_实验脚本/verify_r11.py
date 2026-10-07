"""Verify the review bundle, isolated tests and honest machine qualification.

Passing this program means reproducible review material, not all competition
targets passed. A failed/pending safety metric must remain failed/pending.
"""
import argparse,hashlib,json,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser();parser.add_argument('--output-name',default='R11_offline_review');parser.add_argument('--manifest',type=Path);args=parser.parse_args()
if Path(args.output_name).name!=args.output_name:raise ValueError('Output must be one directory name')
out=ROOT/'07_修复验证'/args.output_name;out.mkdir(parents=True,exist_ok=False)
checks=[]
if args.manifest:
    manifest=json.loads(args.manifest.read_text(encoding='utf8'))
    for row in manifest['files']:
        path=(ROOT/row['path']).resolve()
        if not path.is_relative_to(ROOT.resolve()):raise ValueError('Manifest path escapes bundle')
        with path.open('rb') as stream:assert hashlib.file_digest(stream,'sha256').hexdigest()==row['sha256'],row['path']
    checks.append({'name':'file_manifest','files':len(manifest['files']),'passed':True})
env=dict(os.environ,PYTHONUTF8='1',PYTHONIOENCODING='utf-8',GUARD_R10='0')
for key in list(env):
    if key.startswith('GUARD_R11_'):env.pop(key)
for file in sorted((ROOT/'track2/tests').glob('test_*.py')):
    proc=subprocess.run([sys.executable,str(file)],cwd=ROOT,env=env,capture_output=True,timeout=180)
    (out/(file.stem+'.log')).write_bytes(proc.stdout+proc.stderr)
    checks.append({'name':file.stem,'passed':proc.returncode==0})
summary=ROOT/'07_修复验证/qualification_summary_r11.json'
if summary.exists():
    qualification=json.loads(summary.read_text(encoding='utf8'))
    states=[c['status'] for c in qualification['checks']]
    assert states and all(s in {'pass','fail','pending'} for s in states)
    full=all(s=='pass' for s in states)
    assert qualification.get('all_requirements_pass') is full,'Qualification summary contradicts recorded checks'
    checks.append({'name':'qualification_consistency','passed':True})
else:full=False
(out/'verification.json').write_text(json.dumps({'checks':checks,'review_material_valid':all(c['passed'] for c in checks),'all_competition_targets_passed':full},indent=2))
print('Offline review',sum(c['passed'] for c in checks),'/',len(checks),'checks; recorded full qualification:',full)
sys.exit(int(any(not c['passed'] for c in checks)))
