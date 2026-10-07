"""Fresh full replay with enforcement enabled and explicit CPU denominators.

The gateway-mode application and its PID collector are selected explicitly. Trajectories
are supplied exclusively to the test model. Always restore the normal deployment.
"""
import json
import argparse
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
RANGE = ROOT / '_scratch/competition/agentrange'
OUT = ROOT / '07_修复验证/online_optimized'

def command(args):
    return subprocess.run(args, check=True, capture_output=True, text=True, encoding='utf-8')

def cpu(name):
    text = command(['docker', 'exec', name, 'cat', '/sys/fs/cgroup/cpu.stat']).stdout
    return int(next(line.split()[1] for line in text.splitlines() if line.startswith('usage_usec '))) / 1e6

def main():
    global OUT
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-name', default='online_optimized',
                        help='fresh subdirectory name inside 07_修复验证')
    parser.add_argument('--transport', choices=['httpx', 'aiohttp'], default='httpx')
    parser.add_argument('--gateway-image', default='agentrange-guard-gateway')
    parser.add_argument('--event-rate', type=float, default=0,
                        help='fixed offered events/second; zero uses original sequential driver')
    args = parser.parse_args()
    if args.event_rate < 0:
        raise ValueError('Event rate cannot be negative')
    name = args.output_name
    if not name or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in name):
        raise ValueError('Output name must contain only letters, digits, underscores or hyphens')
    OUT = ROOT / '07_修复验证' / name
    if OUT.exists():
        raise RuntimeError('Output already exists; use a fresh directory for each qualification run')
    (OUT / 'evidence').mkdir(parents=True)
    inventory = ROOT / '07_修复验证/improved_inventory.json'
    (OUT / 'evidence/inventory.json').write_bytes(inventory.read_bytes())
    override = OUT / 'compose.qualification.json'
    override.write_text(json.dumps({'services': {'guard-gateway': {
        'image': args.gateway_image,
        'volumes': [{'type': 'bind', 'source': str(OUT / 'evidence'), 'target': '/evidence'}],
        'environment': {'GUARD_ENFORCE': '1', 'RECORD_ENABLED': '1',
                        'GUARD_HTTP_TRANSPORT': args.transport}}}}), encoding='utf-8')
    compose = ['docker', 'compose', '--project-name', 'agentrange', '-f',
               str(RANGE / 'docker-compose.yml'), '-f', str(RANGE / 'docker-compose.override.yml')]
    if (RANGE/'docker-compose.authfix.yml').exists():
        compose += ['-f', str(RANGE/'docker-compose.authfix.yml')]
    for key in list(os.environ):
        if key.lower() in {'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'}:
            os.environ.pop(key)
    os.environ.update(OPSPILOT_BASE='http://127.0.0.1:8101',
                      LANGFLOW_BASE='http://127.0.0.1:8101/langflow', LLM_STUB_BASE='http://127.0.0.1:8000')
    sys.path[:0] = [str(RANGE / 'scenario-runner'), str(RANGE / 'corpus-generator'), str(RANGE / 'attack')]
    import runner
    from generate import generate, public_record, trajectory_map
    containers = ['agentrange-guard-gateway', 'agentrange-guard-stackd']
    result = {'seed': 1337, 'total': 5200, 'malicious': 80, 'enforcement': True,
              'transport': args.transport, 'gateway_image': args.gateway_image,
              'offered_events_per_second': args.event_rate or None,
              'scope': 'local generated trajectories; not autonomous-model generalization',
              'status': 'incomplete'}
    try:
        # Avoid accidentally measuring two active guards after native-mode use.
        command(compose + ['up', '-d', '--no-build', '--no-deps', 'opspilot-app'])
        command(compose + ['up', '-d', '--no-build', '--no-deps', '--force-recreate', 'guard-stackd'])
        command(compose + ['-f', str(override), 'up', '-d', '--no-build', '--no-deps', 'guard-gateway'])
        for attempt in range(40):
            try:
                urllib.request.urlopen('http://127.0.0.1:8101/health', timeout=2).read()
                break
            except Exception:
                time.sleep(.5)
        else:
            raise RuntimeError('Gateway did not become healthy')
        events = generate()
        runner.inject_trajectories(trajectory_map(events))
        before = {name: cpu(name) for name in containers}
        start = time.perf_counter()
        try:
            result['driver'] = runner.replay_events([public_record(event) for event in events],
                                                   event_rate=args.event_rate)
        finally:
            result['wall_s'] = time.perf_counter() - start
            after = {name: cpu(name) for name in containers}
            result['cpu_seconds'] = {name: after[name] - before[name] for name in containers}
            result['single_core_cpu_percent'] = {
                name: 100 * value / result['wall_s'] for name, value in result['cpu_seconds'].items()}
            ncpu = int(command(['docker', 'info', '--format', '{{.NCPU}}']).stdout.strip())
            result['docker_vm_logical_cpus'] = ncpu
            result['combined_single_core_percent'] = sum(result['single_core_cpu_percent'].values())
            result['combined_vm_capacity_percent'] = result['combined_single_core_percent'] / ncpu
            runner.clear_trajectories()
        time.sleep(1)
        result['status'] = 'completed'
        print(json.dumps(result), flush=True)
    finally:
        (OUT / 'measurement.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        command(compose + ['up', '-d', '--no-build', '--no-deps', 'guard-gateway'])

if __name__ == '__main__':
    main()
