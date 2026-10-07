"""Same-rate cgroup CPU comparison, including cost inside the protected process.

Baseline executes ONLY the inspected, inert local competition trajectories. It is
not a production switch. Native guard and framework evidence are written to
separate directories, then merged without overwriting their original streams.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
RANGE = ROOT / '_scratch/competition/agentrange'

def command(args):
    return subprocess.run(args, check=True, capture_output=True, text=True, encoding='utf-8')

def cpu(name):
    raw = command(['docker', 'exec', name, 'cat', '/sys/fs/cgroup/cpu.stat']).stdout
    return int(next(line.split()[1] for line in raw.splitlines() if line.startswith('usage_usec '))) / 1e6

def get(url):
    return json.loads(urllib.request.urlopen(url, timeout=3).read())

def merge(out, inventory):
    destination = out/'evidence'
    destination.mkdir()
    (destination/'inventory.json').write_bytes(inventory.read_bytes())
    policy=inventory.parent/'result_policy.json'
    if policy.exists(): (destination/'result_policy.json').write_bytes(policy.read_bytes())
    sources = {}
    for directory in [out/'records/inline', out/'records/framework']:
        for file in directory.glob('*.jsonl'):
            sources.setdefault(file.name, []).append(file)
    manifest = []
    for name, files in sources.items():
        rows = []
        for file in files:
            for sequence, line in enumerate(file.read_text(encoding='utf-8').splitlines(), 1):
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError('Evidence row must be an object')
                row['_collector_source'] = file.relative_to(out).as_posix()
                row['_collector_sequence'] = sequence
                rows.append(row)
            manifest.append({'source': file.relative_to(out).as_posix(),
                'sha256': hashlib.sha256(file.read_bytes()).hexdigest()})
        # Wall clocks can jump backwards and random request IDs are not sequence
        # IDs. Preserve each append-only stream's order. Independent collectors have
        # no claimed global causal ordering; retain their provenance explicitly.
        (destination/name).write_text(''.join(json.dumps(row, ensure_ascii=False)+'\n' for row in rows), encoding='utf-8')
    (out/'merge_manifest.json').write_text(json.dumps(manifest, indent=2))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', required=True, choices=['baseline', 'guard'])
    parser.add_argument('--output-name', required=True)
    parser.add_argument('--event-rate', type=float, default=40)
    parser.add_argument('--gateway-image', default='agentrange-guard-gateway-r8')
    parser.add_argument('--official-target', action='store_true',
        help='Mount preserved official application and MCP source without fixture fixes')
    args = parser.parse_args()
    if args.event_rate <= 0 or not args.output_name or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in args.output_name):
        raise ValueError('Use a positive event rate and a simple output directory name')
    out = ROOT/'07_修复验证'/args.output_name
    if out.exists():
        raise RuntimeError('Refusing to mix evidence with an existing run')
    (out/'records').mkdir(parents=True)
    inventory = ROOT/'07_修复验证/R6_static_inventory_final.json'
    if not inventory.exists():
        inventory = ROOT/'07_修复验证/R4_inventory.json'
    if not inventory.exists():
        inventory = ROOT/'07_修复验证/improved_inventory.json'
    (out/'records/inventory.json').write_bytes(inventory.read_bytes())
    policy=ROOT/'05_复现脚本/result_policy.official.json'
    (out/'records/result_policy.json').write_bytes(policy.read_bytes())
    (out/'state').mkdir()
    compose = ['docker', 'compose', '--project-name', 'agentrange', '-f',
        str(RANGE/'docker-compose.yml'), '-f', str(RANGE/'docker-compose.override.yml'),
        '-f', str(RANGE/'docker-compose.authfix.yml')]
    appenv = {'LLM_BASE': 'http://llm-stub:8000/v1',
        'MCP_CUSTOMER_DB': 'http://mcp-customer-db:8000/mcp',
        'MCP_SHELL_RUNNER': 'http://mcp-shell-runner:8000/mcp',
        'MCP_NOTES_SYNC': 'http://mcp-notes-sync:8000/mcp',
        'MCP_THREAT_INTEL': 'http://mcp-threat-intel:8000/mcp',
        'MCP_GITLAB': 'http://mcp-gitlab:8000/mcp',
        'MCP_MONITORING': 'http://mcp-monitoring:8000/mcp',
        'MCP_KNOWLEDGE': 'http://mcp-knowledge:8000/mcp',
        'MCP_SANDBOX_EXEC': 'http://mcp-sandbox-exec:8000/mcp',
        'GUARD_APP_IMPORT': 'api.app:app', 'GUARD_ENFORCE': '1',
        'GUARD_KG':'1','GUARD_R8':'1','GUARD_GRAPH_STATE_PATH':'/state/app.sqlite',
        'GUARD_RESULT_POLICY_PATH':'/policies/results.json',
        'GUARD_AUTH_DIAGNOSTIC_IMPORT': 'api.app:verify_token',
        'GUARD_HTTP_TRANSPORT': 'httpx', 'PYTHONPATH': '/src/collector:/src/detector:/app',
        'INVENTORY_PATH': '/evidence/inventory.json', 'RECORD_DIR': '/evidence/inline',
        'STACK_URL': 'http://guard-stackd:8090/stack'}
    volumes = [{'type': 'bind', 'source': str(ROOT/'track2/collector'), 'target': '/src/collector', 'read_only': True},
        {'type': 'bind', 'source': str(ROOT/'track2/detector'), 'target': '/src/detector', 'read_only': True},
        {'type': 'bind', 'source': str(out/'records'), 'target': '/evidence'}]
    volumes.extend([{'type':'bind','source':str(out/'state'),'target':'/state'},
        {'type':'bind','source':str(policy),'target':'/policies/results.json','read_only':True}])
    config = {'services': {
        'opspilot-app': {'environment': appenv, 'volumes': volumes,
            'command': ['uvicorn', '--app-dir', '/src/collector',
                        'inprocess:app' if args.mode == 'guard' else 'auth_diagnostic_entry:app',
                        '--host', '0.0.0.0', '--port', '8000', '--log-level', 'warning']},
        'guard-gateway': {'image': args.gateway_image,
            'environment': {'RECORD_DIR': '/evidence/framework', 'INVENTORY_PATH': '/evidence/inventory.json',
                'GUARD_HTTP_TRANSPORT': 'aiohttp', 'GUARD_FRAMEWORK_ONLY': '1'},
            'volumes': [{'type': 'bind', 'source': str(out/'records'), 'target': '/evidence'}]}}}
    gateway=config['services']['guard-gateway']
    gateway['environment'].update(GUARD_KG='1',GUARD_R8='1',GUARD_GRAPH_STATE_PATH='/state/gateway.sqlite',
        GUARD_RESULT_POLICY_PATH='/policies/results.json')
    gateway['volumes'].extend([{'type':'bind','source':str(out/'state'),'target':'/state'},
        {'type':'bind','source':str(policy),'target':'/policies/results.json','read_only':True}])
    official_sources = []
    if args.official_target:
        official = ROOT/'06_赛题与第三方/官方靶场原包/agentrange'
        provenance = json.loads((ROOT/'07_修复验证/R4_official_provenance.json').read_text(encoding='utf-8'))
        for item in provenance['official_files']:
            path = official/item['path']
            if hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']:
                raise RuntimeError('Official preserved source checksum mismatch')
            official_sources.append(path)
        config['services']['opspilot-app']['image'] = 'agentrange-opspilot-app-official-r4'
        for name in ['customer-db', 'shell-runner', 'notes-sync', 'threat-intel',
                     'gitlab', 'monitoring', 'knowledge', 'sandbox-exec']:
            config['services']['mcp-'+name] = {'image': 'agentrange-mcp-official-r4'}
    override = out/'compose.native.json'
    override.write_text(json.dumps(config), encoding='utf-8')
    stage = compose + ['-f', str(override)]
    for key in list(os.environ):
        if key.lower() in {'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'}:
            os.environ.pop(key)
    os.environ.update(OPSPILOT_BASE='http://127.0.0.1:8100',
        LANGFLOW_BASE='http://127.0.0.1:8101/langflow', LLM_STUB_BASE='http://127.0.0.1:8000')
    sys.path[:0] = [str(RANGE/'scenario-runner'), str(RANGE/'corpus-generator'), str(RANGE/'attack')]
    import runner
    from generate import generate, public_record, trajectory_map
    names = ['agentrange-opspilot-app-1', 'agentrange-guard-gateway', 'agentrange-guard-stackd']
    result = {'mode': args.mode, 'seed': 1337, 'total': 5200, 'malicious': 80,
        'status': 'incomplete', 'event_rate': args.event_rate,
        'scope': 'protected application CPU included; local inspected template workload'}
    result['official_target_source'] = args.official_target
    if args.official_target:
        result['official_archive_sha256'] = provenance['archive_sha256']
        result['fixture_auth_clock_skew_patch_active'] = False
        result['fixture_mcp_guard_patch_active'] = False
        result['driver_changes'] = 'rate pacing, cached identities and bounded authenticated readiness before timed business; original event generation and attack payloads unchanged'
        result['official_source_deployment'] = 'Built with official Dockerfiles; no Windows whole-source bind mount'
    measured_sources = [p for directory in ['track2/collector', 'track2/detector']
                        for p in (ROOT/directory).glob('*.py')]
    result['runtime_source_sha256'] = {p.relative_to(ROOT).as_posix():
        hashlib.sha256(p.read_bytes()).hexdigest() for p in measured_sources}
    result['driver_source_sha256'] = {str(p.relative_to(ROOT)).replace('\\', '/'):
        hashlib.sha256(p.read_bytes()).hexdigest() for p in [
            RANGE/'scenario-runner/runner.py', RANGE/'scenario-runner/token_readiness.py']}
    try:
        if args.official_target:
            command(stage+['up', '-d', '--no-build', '--no-deps', *[
                name for name in config['services'] if name.startswith('mcp-')]])
        command(stage+['up', '-d', '--no-build', '--no-deps', 'opspilot-app'])
        command(stage+['up', '-d', '--no-build', '--no-deps', '--force-recreate', 'guard-stackd'])
        command(stage+['up', '-d', '--no-build', '--no-deps', 'guard-gateway'])
        for attempt in range(60):
            try:
                get('http://127.0.0.1:8100/health')
                get('http://127.0.0.1:8101/health')
                if args.mode == 'guard':
                    result['initial_native_health'] = get('http://127.0.0.1:8100/agentguard/health')
                break
            except Exception:
                time.sleep(.5)
        else:
            raise RuntimeError('Native qualification services did not become healthy')
        if args.official_target:
            from attest_official_runtime import attest
            result['official_runtime_attestation'] = attest()
        events = generate()
        if args.mode == 'baseline':
            # Prevent this test-only unguarded baseline being used on arbitrary
            # downloaded content. The fixture's execution endpoint is an inert literal.
            text = command(['docker', 'exec', 'agentrange-c2-sink-1', 'python', '-c',
                'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:9100/b").read().decode())']).stdout.strip()
            if text != '"echo beaconed"':
                raise RuntimeError('Fixture command endpoint is not the inspected inert response')
            result['baseline_fixture_check'] = 'inert local endpoint verified'
        runner.inject_trajectories(trajectory_map(events))
        before = {name: cpu(name) for name in names}
        started = time.perf_counter()
        try:
            result['driver'] = runner.replay_events([public_record(event) for event in events], event_rate=args.event_rate)
        finally:
            result['wall_s'] = time.perf_counter()-started
            after = {name: cpu(name) for name in names}
            result['cpu_seconds'] = {name: after[name]-before[name] for name in names}
            result['absolute_single_core_cpu_percent'] = {
                name: 100*value/result['wall_s'] for name, value in result['cpu_seconds'].items()}
            runner.clear_trajectories()
        if args.mode == 'guard':
            result['final_native_health'] = get('http://127.0.0.1:8100/agentguard/health')
        # Graceful recreation flushes both original process writers before merge.
        command(compose+['up', '-d', '--no-build', '--no-deps', 'opspilot-app'])
        command(compose+['up', '-d', '--no-build', '--no-deps', '--force-recreate', 'guard-stackd'])
        command(compose+['up', '-d', '--no-build', '--no-deps', 'guard-gateway'])
        if args.mode == 'guard':
            merge(out, out/'records/inventory.json')
        if any(hashlib.sha256((ROOT/name).read_bytes()).hexdigest() != digest
               for name, digest in result['runtime_source_sha256'].items()):
            raise RuntimeError('Runtime source changed during qualification')
        if any(hashlib.sha256((ROOT/name).read_bytes()).hexdigest() != digest
               for name, digest in result['driver_source_sha256'].items()):
            raise RuntimeError('Driver source changed during qualification')
        result['status'] = 'completed'
        print(json.dumps(result), flush=True)
    finally:
        (out/'measurement.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        if result['status'] != 'completed':
            command(compose+['up', '-d', '--no-build', '--no-deps', 'opspilot-app'])
            command(compose+['up', '-d', '--no-build', '--no-deps', '--force-recreate', 'guard-stackd'])
            command(compose+['up', '-d', '--no-build', '--no-deps', 'guard-gateway'])

if __name__ == '__main__':
    main()
