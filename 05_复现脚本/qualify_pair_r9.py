"""Three controlled same-PID pairs, full original 5200-event workload per phase."""
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time
import urllib.request
import argparse

ROOT = Path(__file__).resolve().parents[1]
RANGE = ROOT/'_scratch/competition/agentrange'
parser = argparse.ArgumentParser()
parser.add_argument('--output-name', default='R9_1_cpu_pair')
args = parser.parse_args()
if not args.output_name or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in args.output_name):
    raise ValueError('Use a simple output directory name')
OUT = ROOT/'07_修复验证'/args.output_name
if OUT.exists():
    raise RuntimeError('Refusing to mix a same-PID experiment with existing data')
def command(args):
    try:
        return subprocess.run(args, check=True, capture_output=True, text=True, encoding='utf-8')
    except subprocess.CalledProcessError as error:
        OUT.mkdir(exist_ok=True, parents=True)
        with (OUT/'command_failure.log').open('a', encoding='utf-8') as log:
            log.write((error.stdout or '')+(error.stderr or ''))
        raise
def get(url):
    return json.loads(urllib.request.urlopen(url, timeout=3).read())
CPU_SPLIT = {}
def cpu(name):
    raw = command(['docker', 'exec', name, 'cat', '/sys/fs/cgroup/cpu.stat']).stdout
    stat = dict(line.split() for line in raw.splitlines())
    CPU_SPLIT[name] = {key: int(stat[key]) for key in ['user_usec', 'system_usec']}
    return int(stat['usage_usec'])/1e6
names = ['agentrange-opspilot-app-1', 'agentrange-guard-gateway', 'agentrange-guard-stackd']
command([sys.executable, str(ROOT/'05_复现脚本/deploy_r3.py'), '--mode', 'inprocess',
         '--official-target', '--evidence-name', OUT.name])
config = json.loads((OUT/'compose.native.json').read_text(encoding='utf-8'))
for service, role in [('opspilot-app', 'native'), ('guard-gateway', 'framework')]:
    spec = config['services'][service]
    spec['environment'].update(GUARD_LOCAL_FIXTURE_BENCHMARK='1', BENCH_ROLE=role)
    spec['volumes'].append({'type': 'bind', 'source': str(ROOT/'track2/bench'),
                            'target': '/src/bench', 'read_only': True})
    spec['environment']['PYTHONPATH'] = '/src/bench:/src/collector:/src/detector:/app'
    for volume in spec['volumes']:
        if volume['target']=='/state':
            state=OUT/'state'/role
            state.mkdir(exist_ok=True,parents=True)
            volume['source']=str(state)
    spec['command'] = ['uvicorn', '--app-dir', '/src/bench', 'bench_ab:app', '--host', '0.0.0.0',
                       '--port', '8000' if role == 'native' else '8080', '--log-level', 'warning']
override = OUT/'compose.benchmark.json'
override.write_text(json.dumps(config, indent=2), encoding='utf-8')
compose = ['docker', 'compose', '-p', 'agentrange', '-f', str(RANGE/'docker-compose.yml'),
           '-f', str(RANGE/'docker-compose.override.yml'), '-f', str(RANGE/'docker-compose.authfix.yml'),
           '-f', str(override)]
result = {'status': 'incomplete', 'method': 'same-PID; full fixed official workload; conservative native idle cost added',
          'pairs': [], 'pair_count_planned':1, 'scope':'single exploratory pair; not stable CPU bound', 'production_entrypoint_changed': False}
sources = [p for directory in ['track2/collector', 'track2/detector', 'track2/bench']
           for p in (ROOT/directory).glob('*.py')]
result['source_sha256'] = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
driver_files = [RANGE/'scenario-runner/runner.py', RANGE/'scenario-runner/token_readiness.py', Path(__file__).resolve(),
    ROOT/'05_复现脚本/deploy_r3.py',ROOT/'05_复现脚本/qualify_inprocess.py',ROOT/'05_复现脚本/result_policy.official.json']
result['driver_source_sha256'] = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in driver_files}
sys.path[:0] = [str(RANGE/'scenario-runner'), str(RANGE/'attack'), str(RANGE/'corpus-generator'), str(ROOT/'05_复现脚本')]
for key in list(os.environ):
    if key.lower() in {'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'}:
        os.environ.pop(key)
os.environ.update(OPSPILOT_BASE='http://127.0.0.1:8100', LANGFLOW_BASE='http://127.0.0.1:8101/langflow',
                  LLM_STUB_BASE='http://127.0.0.1:8000')
import runner
from generate import generate, public_record, trajectory_map
from qualify_inprocess import merge
urls = ['http://127.0.0.1:8100/agentguard/health', 'http://127.0.0.1:8101/health']
def wait_health(period=None):
    for attempt in range(60):
        try:
            rows = [get(url) for url in urls]
            if all(r.get('benchmark_only') and (period is None or r['period'] == period) for r in rows):
                return rows
        except Exception:
            pass
        time.sleep(.5)
    raise RuntimeError('Benchmark entrypoints did not become ready')
def transition(mode, period):
    control = OUT/'records/bench_control.json'
    temporary = control.with_suffix('.tmp')
    temporary.write_text(json.dumps({'mode': mode, 'period': period}), encoding='utf-8')
    temporary.replace(control)
    for name in names[:2]:
        command(['docker', 'kill', '--signal', 'USR1' if mode == 'baseline' else 'USR2', name])
    health = wait_health(period)
    assert all(r['mode'] == mode and r['guard']['enforcement'] == (mode == 'guard') for r in health)
    return health
try:
    command(compose+['up', '-d', '--no-build', '--no-deps', 'opspilot-app', 'guard-gateway'])
    command(compose+['up', '-d', '--no-build', '--no-deps', '--force-recreate', 'guard-stackd'])
    initial = wait_health()
    identity_format = '{{.Id}}|{{.State.StartedAt}}|{{.State.Pid}}'
    identities = [command(['docker', 'inspect', name, '--format', identity_format]).stdout.strip() for name in names]
    result['container_identity_start_pid'] = dict(zip(names, identities))
    from attest_official_runtime import attest
    result['official_runtime_attestation'] = attest()
    text = command(['docker', 'exec', 'agentrange-c2-sink-1', 'python', '-c',
        'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:9100/b").read().decode())']).stdout.strip()
    assert text == '"echo beaconed"'
    events = generate()
    public = [public_record(event) for event in events]
    transition('baseline', 'idle')
    before = cpu(names[0])
    start = time.perf_counter()
    time.sleep(5)
    result['conservative_native_idle_percent'] = 100*(cpu(names[0])-before)/(time.perf_counter()-start)
    for pair, order in [(1, ['baseline', 'guard'])]:
        phases = {}
        for mode in order:
            period = f'pair{pair}_{mode}'
            transition(mode, period)
            assert identities == [command(['docker', 'inspect', name, '--format', identity_format]).stdout.strip() for name in names]
            runner.inject_trajectories(trajectory_map(events))
            before = {name: cpu(name) for name in names}
            split_before = {name: dict(CPU_SPLIT[name]) for name in names}
            started = time.perf_counter()
            phase = {'status': 'incomplete', 'period': period, 'mode': mode}
            print('Starting same-PID '+period, flush=True)
            try:
                phase['driver'] = runner.replay_events(public, event_rate=40)
                phase['status'] = 'completed'
            finally:
                phase['wall_s'] = time.perf_counter()-started
                after = {name: cpu(name) for name in names}
                phase['cpu_seconds'] = {name: after[name]-before[name] for name in names}
                phase['cpu_split_seconds'] = {name: {key: (CPU_SPLIT[name][key]-split_before[name][key])/1e6
                    for key in ['user_usec', 'system_usec']} for name in names}
                phase['absolute_single_core_cpu_percent'] = {name: 100*v/phase['wall_s'] for name,v in phase['cpu_seconds'].items()}
                runner.clear_trajectories()
                phase['health'] = wait_health(period)
                (OUT/(period+'_measurement.json')).write_text(json.dumps(phase, indent=2), encoding='utf-8')
            phases[mode] = phase
        base, guard = [phases[m]['absolute_single_core_cpu_percent'] for m in ['baseline', 'guard']]
        increment = guard[names[0]]-base[names[0]]+guard[names[1]]+guard[names[2]]+result['conservative_native_idle_percent']
        result['pairs'].append({'pair': pair, 'order': order, 'baseline': phases['baseline'], 'guard': phases['guard'],
                                'incremental_single_core_cpu_percent': increment})
        print(f'Same-PID pair {pair}: {increment:.4f}%', flush=True)
        (OUT/'measurement.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    # Transition rotates and flushes the last period before copying its streams.
    transition('guard', 'final_flush')
    for pair in range(1, 2):
        destination = OUT/f'pair{pair}_guard'
        (destination/'records').mkdir(parents=True)
        import shutil
        for directory in ['inline', 'framework']:
            shutil.copytree(OUT/'records'/f'pair{pair}_guard'/directory, destination/'records'/directory)
        inventory = OUT/'records/inventory.json'
        merge(destination, inventory)
        phase = result['pairs'][pair-1]['guard']
        phase['runtime_source_sha256'] = result['source_sha256']
        phase['driver_source_sha256'] = result['driver_source_sha256']
        (destination/'measurement.json').write_text(json.dumps(phase, indent=2), encoding='utf-8')
    values = [r['incremental_single_core_cpu_percent'] for r in result['pairs']]
    result.update(status='completed', mean=statistics.mean(values), max=max(values),
        stdev=None, all_observed_pairs_below_5pct=all(v < 5 for v in values),
        container_ids_unchanged=True)
    assert all(hashlib.sha256((ROOT/rel).read_bytes()).hexdigest() == sha for rel,sha in result['source_sha256'].items())
    assert all(hashlib.sha256((ROOT/rel).read_bytes()).hexdigest() == sha for rel,sha in result['driver_source_sha256'].items())
finally:
    (OUT/'measurement.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    if result['status'] != 'completed':
        for name in names[:2]:
            log = subprocess.run(['docker', 'logs', name, '--tail', '80'], capture_output=True,
                                  text=True, encoding='utf-8', errors='replace')
            (OUT/(name+'_failure.log')).write_text(log.stdout+log.stderr, encoding='utf-8')
    command([sys.executable, str(ROOT/'05_复现脚本/deploy_r3.py'), '--mode', 'inprocess',
             '--official-target', '--evidence-name', OUT.name+'_restored'])
print(json.dumps({'status': result['status'], 'max': result.get('max'), 'mean': result.get('mean')}, ensure_ascii=False))
