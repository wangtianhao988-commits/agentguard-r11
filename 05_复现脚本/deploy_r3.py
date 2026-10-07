"""Configure the qualified native mode, or restore the HTTP gateway mode.

Only touches the agentrange compose project. Absolute bind paths are regenerated
from the current extraction directory so archived measurement paths are not used.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
RANGE = ROOT / '_scratch/competition/agentrange'

def run(args):
    subprocess.run(args, check=True, cwd=ROOT)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['inprocess', 'gateway'], default='inprocess')
    parser.add_argument('--build', action='store_true')
    parser.add_argument('--gateway-image', default='agentrange-guard-gateway-r10-1')
    parser.add_argument('--native-image', default='agentrange-opspilot-app-r10')
    parser.add_argument('--no-r8', action='store_true')
    parser.add_argument('--result-policy', type=Path)
    parser.add_argument('--no-knowledge-graph', action='store_true')
    parser.add_argument('--task-policy', type=Path)
    parser.add_argument('--model-url', help='Deployment-owned local model for the authenticated R11 finite-plan mode')
    parser.add_argument('--r11-sparse', action='store_true', help='Experimental sparse prefilter, requires contextual verifier')
    parser.add_argument('--intent-url', help='Deployment-owned local task verifier; experimental, not qualified')
    parser.add_argument('--official-target', action='store_true')
    parser.add_argument('--evidence-name', default='R10_deployment')
    args = parser.parse_args()
    if args.r11_sparse and not args.intent_url:parser.error('Sparse prefilter requires --intent-url; standalone false-positive rate is not qualified')
    if (args.intent_url or args.model_url) and args.mode!='inprocess':parser.error('R11 model configuration requires inprocess integration')
    from urllib.parse import urlsplit
    for candidate in (args.intent_url,args.model_url):
        if candidate:
            parsed=urlsplit(candidate)
            if parsed.scheme not in {'http','https'} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                parser.error('Model endpoint must be a fixed HTTP(S) URL without embedded credentials, query or fragment')
    if args.task_policy and args.mode != 'inprocess':
        parser.error('--task-policy requires authenticated inprocess integration')
    base = ['docker', 'compose', '--project-name', 'agentrange', '-f',
            str(RANGE/'docker-compose.yml'), '-f', str(RANGE/'docker-compose.override.yml')]
    if args.build:
        run(base + ['build'])
        run(['docker', 'build', '-t', 'agentrange-opspilot-app-r3', '-f',
             str(ROOT/'07_修复验证/R3诊断/Dockerfile.authfix'), str(RANGE)])
        run(['docker', 'build', '-t', args.gateway_image, '-f',
             str(ROOT/'track2/collector/Dockerfile'), str(ROOT/'track2')])
        if args.official_target:
            official = ROOT/'06_赛题与第三方/官方靶场原包/agentrange'
            run(['docker', 'build', '-t', 'agentrange-opspilot-app-official-r4', '-f',
                 str(official/'opspilot-app/Dockerfile'), str(official)])
            run(['docker', 'build', '-t', 'agentrange-mcp-official-r4', str(official/'mcp')])
            run(['docker','build','-t','agentrange-opspilot-app-r10','-f',
                 str(ROOT/'track2/collector/Dockerfile.native-r10'),str(ROOT/'track2')])
    compose = base + ['-f', str(RANGE/'docker-compose.authfix.yml')]
    if args.mode == 'inprocess':
        template = ROOT/'07_修复验证/R3_native_guard_40eps/compose.native.json'
        config = json.loads(template.read_text(encoding='utf-8'))
        if Path(args.evidence_name).name != args.evidence_name:
            raise ValueError('evidence-name must be a directory name')
        records = ROOT/'07_修复验证'/args.evidence_name/'records'
        records.mkdir(parents=True, exist_ok=True)
        inventory = ROOT/'07_修复验证/R6_static_inventory_final.json'
        if not inventory.exists():
            inventory = ROOT/'07_修复验证/R4_inventory.json'
        if not inventory.exists():
            inventory = ROOT/'07_修复验证/improved_inventory.json'
        shutil.copy2(inventory, records/'inventory.json')
        # Enrich only deployment-owned literal source registrations. Tool-return
        # metadata cannot create a certificate; original source is later attested.
        import sys
        sys.path.insert(0,str(ROOT/'track2/detector'))
        from source_contract import certify
        inventory_doc=json.loads((records/'inventory.json').read_text(encoding='utf-8'))
        official_source=ROOT/'06_赛题与第三方/官方靶场原包/agentrange'
        for asset in inventory_doc.get('asset_graph',{}).get('assets',[]):
            if asset.get('kind')!='tool':continue
            attrs=asset.get('attributes',{});registration=attrs.get('source_registration') or {}
            if not registration.get('file') or not registration.get('handler'):continue
            source=(official_source/registration['file']).resolve()
            if not source.is_relative_to(official_source.resolve()):raise ValueError('Source registration outside deployment')
            proof=certify(source.read_text(encoding='utf-8'),registration['handler'])
            if proof:attrs['source_effect_certificate']=proof
        (records/'inventory.json').write_text(json.dumps(inventory_doc,ensure_ascii=False,indent=2),encoding='utf-8')
        policy=args.result_policy or ROOT/'05_复现脚本/result_policy.official.json'
        policy=policy.resolve(strict=True)
        import sys
        sys.path.insert(0,str(ROOT/'track2/detector'))
        from intervention import ResultPolicies
        ResultPolicies(json.loads(policy.read_text(encoding='utf-8')))
        shutil.copy2(policy,records/'result_policy.json')
        sources = {'/src/collector': ROOT/'track2/collector',
                   '/src/detector': ROOT/'track2/detector', '/evidence': records}
        for service in config['services'].values():
            for volume in service.get('volumes', []):
                volume['source'] = str(sources[volume['target']])
        config['services']['guard-gateway']['image'] = args.gateway_image
        for name in ['opspilot-app', 'guard-gateway']:
            config['services'][name]['environment']['GUARD_KG'] = '0' if args.no_knowledge_graph else '1'
            spec=config['services'][name]
            spec['environment']['GUARD_R8']='0' if args.no_r8 else '1'
            state=ROOT/'09_运行状态'/name
            state.mkdir(exist_ok=True,parents=True)
            spec['volumes'].append({'type':'bind','source':str(state),'target':'/state','read_only':False})
            spec['volumes'].append({'type':'bind','source':str(policy),'target':'/policies/results.json','read_only':True})
            spec['environment']['GUARD_RESULT_POLICY_PATH']='/policies/results.json'
            spec['environment']['GUARD_GRAPH_STATE_PATH']='/state/r8.sqlite'
            spec['environment']['GUARD_R10']='1'
            if args.r11_sparse:spec['environment']['GUARD_R11_SPARSE']='1'
            spec['environment']['GUARD_R10_MODEL_PATH']='/src/models/r10'
            spec['environment']['GUARD_R10_DATA_POLICY_PATH']='/policies/data.r10.json'
            spec['volumes'].append({'type':'bind','source':str(ROOT/'track2/models'),'target':'/src/models','read_only':True})
            spec['volumes'].append({'type':'bind','source':str(ROOT/'05_复现脚本/data_policy.official.r10.json'),'target':'/policies/data.r10.json','read_only':True})
        app=config['services']['opspilot-app']
        # The framework proxy has no authenticated user task. Task judgments
        # belong to the native application, never to the framework HTTP layer.
        if args.intent_url:app['environment']['GUARD_R11_INTENT_URL']=args.intent_url
        app['environment']['GUARD_R10_CONTROL_POLICY_PATH']='/policies/control.r10.json'
        app['environment']['GUARD_R10_AUTH_IMPORT']='api.app:current_identity'
        if args.model_url:
            app['environment']['GUARD_R11_MODEL_URL']=args.model_url
        app['volumes'].append({'type':'bind','source':str(ROOT/'05_复现脚本/control_policy.official.r10.json'),'target':'/policies/control.r10.json','read_only':True})
        config['services']['opspilot-app']['environment']['GUARD_AUTH_DIAGNOSTIC_IMPORT'] = 'api.app:verify_token'
        if args.official_target:
            official = ROOT/'06_赛题与第三方/官方靶场原包/agentrange'
            import hashlib
            provenance = json.loads((ROOT/'07_修复验证/R4_official_provenance.json').read_text(encoding='utf-8'))
            for item in provenance['official_files']:
                if hashlib.sha256((official/item['path']).read_bytes()).hexdigest() != item['sha256']:
                    raise RuntimeError('Official source changed')
            app = config['services']['opspilot-app']
            app['image'] = args.native_image
            for name in ['customer-db', 'shell-runner', 'notes-sync', 'threat-intel',
                         'gitlab', 'monitoring', 'knowledge', 'sandbox-exec']:
                config['services']['mcp-'+name] = {'image': 'agentrange-mcp-official-r4'}
        if args.task_policy:
            policy = args.task_policy.resolve(strict=True)
            # Validate before replacing containers, rather than discovering invalid
            # configuration only after the application is unavailable.
            import sys
            sys.path.insert(0, str(ROOT/'track2/detector'))
            from task_policy import TaskPolicies
            TaskPolicies.load(policy)
            app = config['services']['opspilot-app']
            app['volumes'].append({'type': 'bind', 'source': str(policy),
                                  'target': '/policies/tasks.json', 'read_only': True})
            app['environment']['GUARD_TASK_POLICY_PATH'] = '/policies/tasks.json'
        override = records.parent/'compose.native.json'
        override.write_text(json.dumps(config, indent=2), encoding='utf-8')
        compose += ['-f', str(override)]
    services = subprocess.run(compose + ['config', '--services'], check=True,
                              capture_output=True, text=True).stdout.splitlines()
    # Do not restart the old stack collector while its former target PID namespace
    # is being replaced. The scanner is a separate, explicitly invoked batch job.
    services = [name for name in services if name not in {'guard-stackd', 'guard-inventory'}]
    run(compose + ['up', '-d', '--no-build', *services])
    # The collector shares the application's PID namespace; recreation must follow
    # replacement of the application even when its own configuration is unchanged.
    run(compose + ['up', '-d', '--no-build', '--no-deps', '--force-recreate', 'guard-stackd'])
    print('Configured mode:', args.mode)

if __name__ == '__main__':
    main()
