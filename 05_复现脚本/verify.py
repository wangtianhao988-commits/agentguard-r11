"""Reproduce measurements without confusing completion with competition compliance."""
import json
import os
from pathlib import Path
import subprocess
import sys
import argparse

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / '07_修复验证'
parser = argparse.ArgumentParser()
parser.add_argument('--qualification', default='R8_final_guard_40eps')
parser.add_argument('--output-name', default='')
options = parser.parse_args()
if Path(options.qualification).name != options.qualification:
    raise ValueError('qualification must be a directory name')
if options.output_name:
    if Path(options.output_name).name != options.output_name:
        raise ValueError('output-name must be a directory name')
    OUT = OUT / options.output_name
    OUT.mkdir(parents=True, exist_ok=True)
EVIDENCE = ROOT / '07_修复验证' / options.qualification / 'evidence'
if not (EVIDENCE.parent / 'measurement.json').exists():
    if options.qualification != 'online_optimized':
        raise RuntimeError('Selected qualification is missing')
    EVIDENCE = ROOT / '04_实验证据'
elif json.loads((EVIDENCE.parent / 'measurement.json').read_text())['status'] != 'completed':
    raise RuntimeError('Online qualification is incomplete; refusing to score partial evidence')
INVENTORY = ROOT / '07_修复验证/R8_static_inventory.json'
if not INVENTORY.exists():
    INVENTORY = ROOT / '07_修复验证/R6_static_inventory_final.json'
if not INVENTORY.exists():
    INVENTORY = ROOT / '07_修复验证/R4_inventory.json'
if not INVENTORY.exists():
    INVENTORY = ROOT / '07_修复验证/improved_inventory.json'
if not INVENTORY.exists():
    INVENTORY = ROOT / '04_实验证据/inventory.json'
CHECKS = [
    ('runtime', ['track2/eval/evaluate.py','--evidence',str(EVIDENCE),'--json',str(OUT/'runtime.json')]),
    ('enforcement',['track2/eval/eval_enforcement.py','--evidence',str(EVIDENCE),'--json',str(OUT/'enforcement.json')]),
    ('inventory',['track2/eval/eval_inventory.py','--inventory',str(INVENTORY),'--json',str(OUT/'inventory.json')]),
    ('consistency',['track2/eval/consistency.py','--evidence',str(EVIDENCE)]),
    ('r8_audit',['track2/eval/r8_audit.py','--evidence',str(EVIDENCE),'--json',str(OUT/'r8_audit.json')]),
    ('regressions',['track2/tests/test_regressions.py']),
    ('native_stack',['track2/tests/test_native_stack.py']),
    ('knowledge_graph',['track2/tests/test_knowledge_graph.py']),
    ('security_graph',['track2/tests/test_security_graph.py']),
    ('intervention',['track2/tests/test_intervention.py']),
    ('r8_authorization',['track2/tests/test_r8_authorization.py']),
    ('r8_audit_regressions',['track2/tests/test_r8_audit.py']),
    ('framework_stack',['track2/tests/test_framework_stack.py']),
    ('benign',['track2/eval/benign_stress.py']),
    ('order',['track2/eval/order_independence.py','--evidence',str(EVIDENCE)]),
    ('seed',['track2/eval/seed_holdout.py']),
    ('search',['track2/adversarial/search.py']),
    ('round',['track2/adversarial/round.py']),
    ('memory_round',['track2/adversarial/memory_round.py']),
    ('memory',['track2/generalization/memory_poisoning.py']),
    ('alt',['track2/generalization/run_alt.py']),
    ('backdoor',['track2/generalization/code_backdoor.py']),
    ('holdout',['track2/eval/holdout_injecagent.py']),
    ('external_env',['track2/eval/run_injecagent_env.py']),
    ('external',['track2/eval/run_injecagent.py']),
    ('report',['track2/report/audit_report.py','--evidence',str(EVIDENCE),
               '--out',str(OUT/'攻击链路审计报告.md')]),
]

def main():
    OUT.mkdir(exist_ok=True)
    results = []
    for name, args in CHECKS:
        try:
            p = subprocess.run([sys.executable,*args], cwd=ROOT, capture_output=True,
                timeout=120, env=dict(os.environ,GUARD_KG='1',GUARD_R8='1',PYTHONIOENCODING='utf-8',PYTHONDONTWRITEBYTECODE='1'))
            output = (p.stdout+p.stderr).decode('utf-8',errors='replace')
            (OUT/(name+'.log')).write_text(output,encoding='utf-8')
            status = ('completed' if p.returncode == 0 else
                      'threshold_not_met' if name == 'inventory' and p.returncode == 1
                      else 'failed')
            result = {'name':name,'command':args,'exit_code':p.returncode,'status':status}
        except subprocess.TimeoutExpired:
            result = {'name':name,'status':'failed','error':'timeout'}
        results.append(result)
        print(f"{name}: {result['status']}")
    (OUT/'verification.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
    print('Measurements completed are not proof that all five competition metrics pass.')
    return 2 if any(r['status']=='failed' for r in results) else (
        1 if any(r['status']=='threshold_not_met' for r in results) else 0)

if __name__ == '__main__':
    raise SystemExit(main())
