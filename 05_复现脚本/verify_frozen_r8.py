"""Score each frozen R8 replay, then verify a byte-identical review copy."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys
import argparse

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'07_修复验证'
parser = argparse.ArgumentParser()
parser.add_argument('--cpu-name', default='R8_cpu_qualified')
parser.add_argument('--review-name', default='R8_final_guard_40eps')
parser.add_argument('--output-name', default='R8_final_validation')
options = parser.parse_args()
assert all(Path(value).name == value for value in vars(options).values())
current = OUT/options.cpu_name
measurement = json.loads((current/'measurement.json').read_text(encoding='utf-8'))
assert measurement['status'] == 'completed'
assert measurement['all_observed_pairs_below_5pct']
for field in ['source_sha256', 'driver_source_sha256']:
    for relative, digest in measurement[field].items():
        assert hashlib.sha256((ROOT/relative).read_bytes()).hexdigest() == digest
for pair in measurement['pairs']:
    for health in pair['guard']['health']:
        guard = health['guard']
        assert guard['errors'] == 0 and health['records_dropped'] == {}
        kg = guard['knowledge_graph']
        assert kg['enabled'] and not kg['saturated']
        assert kg['observation_errors'] == 0
        assert kg.get('version')=='R8' and kg['persistence'] and not kg['expired']
        assert set(kg['features'])=={'joint','multi_hop','persistence','planner','isolation'}

env = dict(os.environ, GUARD_KG='1', GUARD_R8='1', PYTHONIOENCODING='utf-8', PYTHONDONTWRITEBYTECODE='1')
results = []
for pair in range(1, 4):
    evidence = current/f'pair{pair}_guard/evidence'
    output = current/f'pair{pair}_validation'
    output.mkdir(exist_ok=True)
    for name, arguments in [
        ('runtime', ['track2/eval/evaluate.py', '--json', str(output/'runtime.json')]),
        ('enforcement', ['track2/eval/eval_enforcement.py', '--json', str(output/'enforcement.json')]),
        ('consistency', ['track2/eval/consistency.py']),
        ('r8_audit', ['track2/eval/r8_audit.py','--json',str(output/'r8_audit.json')])]:
        process = subprocess.run([sys.executable, *arguments, '--evidence', str(evidence)],
                                 cwd=ROOT, capture_output=True, env=env)
        (output/(name+'.log')).write_text((process.stdout+process.stderr).decode('utf-8', errors='replace'), encoding='utf-8')
        results.append({'pair': pair, 'check': name, 'exit_code': process.returncode})
        assert process.returncode == 0, f'{pair} {name} failed'
    stacks = [json.loads(line) for line in (evidence/'code_stack.jsonl').read_text(encoding='utf-8').splitlines()]
    agent = [row for row in stacks if row.get('capture_target') == 'protected-agent']
    framework = [row for row in stacks if row.get('capture_target') == 'guard-gateway']
    decisions=[json.loads(line) for line in (evidence/'guard_decision.jsonl').read_text(encoding='utf-8').splitlines()]
    expected=sum(r.get('point') in {'mcp','result'} and r['action'] in {'BLOCK','ALERT'} for r in decisions)
    assert len(agent)==expected and len(framework)==24
    assert all(any(frame['fn'] == 'call_mcp' for thread in row['threads'] for frame in thread['frames']) for row in agent)
    assert all(not row['upstream_forwarded'] and row['stage'] == 'pre-upstream' for row in framework)
    assert all(any(frame['fn'] == 'obs_e_langflow' for thread in row['threads'] for frame in thread['frames']) for row in framework)
    print(f'pair {pair}: detection, enforcement, consistency and stack targets passed', flush=True)
(current/'replay_validation.json').write_text(json.dumps(results, indent=2), encoding='utf-8')

destination = OUT/options.review_name
if destination.exists():
    # A review copy may already have shipped. Verify it instead of overwriting
    # historical streams during repeated offline verification.
    for source in (current/'pair3_guard').rglob('*'):
        if source.is_file():
            target = destination/source.relative_to(current/'pair3_guard')
            assert target.exists() and source.read_bytes() == target.read_bytes()
else:
    shutil.copytree(current/'pair3_guard', destination)
(destination/'derivation.json').write_text(json.dumps({
    'derived_from': '07_修复验证/'+options.cpu_name+'/pair3_guard',
    'purpose': 'Exact byte copy for final review; not an additional replay'}, indent=2), encoding='utf-8')
raise SystemExit(subprocess.run([sys.executable, '05_复现脚本/verify.py',
    '--qualification', destination.name, '--output-name', options.output_name], cwd=ROOT, env=env).returncode)
