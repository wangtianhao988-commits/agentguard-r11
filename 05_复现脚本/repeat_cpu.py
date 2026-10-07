"""Fixed-count paired qualifications; retain every run and failure."""
from pathlib import Path
import json
import statistics
import subprocess
import sys
import argparse

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'07_修复验证'
results = []
parser = argparse.ArgumentParser()
parser.add_argument('--pairs', type=int, choices=[3, 5], default=5)
parser.add_argument('--prefix', default='R6')
parser.add_argument('--resume', action='store_true')
args = parser.parse_args()
if not args.prefix or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in args.prefix):
    raise ValueError('Use a simple output prefix')
for pair in range(1, args.pairs+1):
    order = ['baseline', 'guard'] if pair % 2 else ['guard', 'baseline']
    rows = {}
    for mode in order:
        name = f'{args.prefix}_pair{pair}_{mode}_40eps'
        print(f'Starting {name}', flush=True)
        if not args.resume or not (OUT/name/'measurement.json').exists():
            subprocess.run([sys.executable, str(Path(__file__).with_name('qualify_inprocess.py')),
                            '--mode', mode, '--official-target', '--output-name', name,
                            '--gateway-image', 'agentrange-guard-gateway-r6', '--event-rate', '40'], check=True)
        row = json.loads((OUT/name/'measurement.json').read_text(encoding='utf-8'))
        assert row['status'] == 'completed'
        for field in ['runtime_source_sha256', 'driver_source_sha256']:
            for rel, sha in row[field].items():
                import hashlib
                assert hashlib.sha256((ROOT/rel).read_bytes()).hexdigest() == sha
        rows[mode] = row
    baseline = rows['baseline']['absolute_single_core_cpu_percent']
    guard = rows['guard']['absolute_single_core_cpu_percent']
    increment = (guard['agentrange-opspilot-app-1']-baseline['agentrange-opspilot-app-1']
                 + guard['agentrange-guard-gateway']+guard['agentrange-guard-stackd'])
    results.append({'pair': pair, 'order': order, 'incremental_single_core_cpu_percent': increment,
                    'baseline': rows['baseline'], 'guard': rows['guard']})
    (OUT/(args.prefix+'_cpu_pairs_partial.json')).write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(f'Pair {pair}: incremental single-core CPU {increment:.4f}%', flush=True)
values = [r['incremental_single_core_cpu_percent'] for r in results]
critical = 4.302653 if len(values) == 3 else 2.776445
summary = {'pairs': results, 'n': len(values), 'min': min(values), 'max': max(values),
           'mean': statistics.mean(values), 'stdev': statistics.stdev(values),
           'mean_95pct_t_interval': [statistics.mean(values)-critical*statistics.stdev(values)/(len(values)**.5),
                                    statistics.mean(values)+critical*statistics.stdev(values)/(len(values)**.5)],
           'all_observed_pairs_below_5pct': all(v < 5 for v in values),
           'scope': 'this host, fixed official templates, 40 offered events/s; exploratory fixed-count replication, not proof for all loads or instantaneous CPU'}
(OUT/(args.prefix+'_cpu_repeat.json')).write_text(json.dumps(summary, indent=2), encoding='utf-8')
print(json.dumps({k:v for k,v in summary.items() if k != 'pairs'}), flush=True)
