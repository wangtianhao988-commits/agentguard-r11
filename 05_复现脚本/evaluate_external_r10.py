"""Independent replay; no fabricated calls following an intervention."""
import argparse,hashlib,importlib.util,json,os,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'07_修复验证/external_r10'
parser=argparse.ArgumentParser();parser.add_argument('--version',choices=['R9.1','R10_initial','R10'],required=True);parser.add_argument('--output-name');parser.add_argument('--development',action='store_true',help='Previously used R10 traces; never report as an independent test');parser.add_argument('--benign-only',action='store_true',help='Development utility probe only; no attack recall claim');parser.add_argument('--dataset-name');args=parser.parse_args()
if args.benign_only and not args.development:parser.error('benign-only is a development probe')
if args.development:OUT=ROOT/'07_修复验证/development_R10'
if args.dataset_name:
    if Path(args.dataset_name).name!=args.dataset_name:parser.error('Dataset must be a single directory name')
    OUT=ROOT/'07_修复验证'/args.dataset_name
protocol=json.loads((OUT/'protocol.json').read_text());project=ROOT if args.version=='R10' else ROOT/'baselines'/('R9_1' if args.version=='R9.1' else 'R10_initial')
if not args.development:
    for path,digest in protocol['sources'][args.version].items():assert hashlib.sha256((project/path).read_bytes()).hexdigest()==digest
    for key,value in protocol.get('runtime_configuration',{}).items():
        if key not in {'GUARD_R11_ACTION','GUARD_R11_SPARSE','GUARD_R11_INTENT_URL','GUARD_R11_MODEL_REVISION','GUARD_R11_VERIFIER_TIMEOUT'}:raise ValueError('Unrecognized frozen runtime option')
        if os.environ.get(key)!=value:raise ValueError('Frozen runtime option mismatch: '+key)
    for path,digest in protocol.get('r11_model_assets',{}).items():assert hashlib.sha256((project/path).read_bytes()).hexdigest()==digest
if args.version!='R9.1':
    for path,digest in protocol['model_assets_by_version'][args.version].items():assert hashlib.sha256((project/'track2/models/r10'/path).read_bytes()).hexdigest()==digest
sys.path[:0]=[str(project/'track2/collector'),str(project/'track2/detector')]
os.environ.update(GUARD_KG='1',GUARD_R8='1',GUARD_R9='1',GUARD_R10='0' if args.version=='R9.1' else '1',GUARD_R10_MODEL_PATH=str(project/'track2/models/r10'))
for key in ['INVENTORY_PATH','GUARD_RESULT_POLICY_PATH','GUARD_KG_COMPONENTS','GUARD_R8_COMPONENTS','GUARD_R10_DATA_POLICY_PATH','GUARD_R10_COMPONENTS','GUARD_GRAPH_STATE_PATH']:os.environ.pop(key,None)
import rules,session
from inline_guard import InlineGuard
spec=importlib.util.spec_from_file_location('metadata_reader',OUT/'metadata_reader.py');reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
catalogs=reader.metadata()
for suite,tools in catalogs.items():
    for name,attrs in tools.items():session.register_tool(suite,name,attrs['input_schema'],attrs['description'])
output_name=args.output_name or args.version
assert Path(output_name).name==output_name,'Output must be a directory name'
destination=OUT/'results'/output_name;destination.mkdir(parents=True,exist_ok=False)
(destination/'tool_metadata.json').write_text(json.dumps(catalogs,indent=2))
results=[];started=time.perf_counter()
def content_text(value):
    if value is None:return ''
    if isinstance(value,str):return value
    if isinstance(value,list) and all(isinstance(x,dict) and x.get('type')=='text' and isinstance(x.get('content',x.get('text')),str) for x in value):
        return '\n'.join(x.get('content',x.get('text')) for x in value)
    raise ValueError('Unsupported archived message content; not a detection')
with tempfile.TemporaryDirectory(prefix='r10_external_') as state:
    for entry in json.loads((OUT/'selection.json').read_text()):
        trace=json.loads((OUT/'raw'/entry['path']).read_text(encoding='utf-8'));suite=trace['suite_name'];tools=catalogs[suite]
        if args.benign_only and trace['attack_type'] not in (None,'none'):continue
        rules.clear_cross_session_state();rules.reset_knowledge_graph()
        rules._R8_INVENTORY={'asset_graph':{'assets':[{'kind':'tool','name':suite+'.'+name,'attributes':attrs} for name,attrs in tools.items()]}}
        rules._R8_RESULT_POLICY={'version':1,'tools':[]}
        os.environ['GUARD_GRAPH_STATE_PATH']=str(Path(state)/(str(len(results))+'.sqlite'))
        guard=InlineGuard();sid='external-session';s=guard._session(sid)
        s.prompt=next((content_text(m.get('content')) for m in trace['messages'] if m['role']=='user'),'');s.identity={'sub':'archived-benchmark-user','scope':{}}
        pending={};decisions=[];rejected=None;result_refusal=None;unknown=[];semantic_incomplete=0
        for index,msg in enumerate(trace['messages']):
            if msg['role']=='assistant':
                for ordinal,call in enumerate(msg.get('tool_calls') or []):
                    binding_id=call.get('id') or f'archive-message-{index}-call-{ordinal}'
                    if call['function'] not in tools:unknown.append(call['function'])
                    decision=guard.check_tool_call(sid,suite,call['function'],call['args'],call_id=binding_id)
                    row={'message_index':index,'call_id':binding_id,'archive_call_id':call['id'],'function':call['function'],**decision.to_json()};decisions.append(row)
                    if decision.blocked:rejected=row;break
                    pending[binding_id]=call
                if rejected:break
            elif msg['role']=='tool':
                rid=msg['tool_call_id']
                if not rid:
                    source=msg.get('tool_call');assert isinstance(source,dict),'Missing null-ID call binding'
                    matches=[key for key,call in pending.items() if call['function']==source['function'] and call['args']==source['args']]
                    assert len(matches)==1,'Ambiguous archived null-ID return: not valid detection evidence'
                    rid=matches[0]
                assert rid in pending,'Unmatched actual tool return'
                body={'jsonrpc':'2.0','id':rid,'result':content_text(msg.get('content'))}
                delivered,audit=guard.observe_tool_result(sid,rid,body,ok=msg.get('error') is None);pending.pop(rid)
                if audit and audit.get('action')=='DENY_RESULT':result_refusal={'message_index':index,'call_id':rid,'audit':audit};break
        evaluation_trace={**trace,'messages':[{**m,'content':content_text(m.get('content'))} for m in trace['messages']]}
        first=reader.injection_index(evaluation_trace);attacked=trace['attack_type'] not in (None,'none')
        verifier_state=guard.r10.snapshot().get('contextual_intent') if guard.r10 else None
        verifier_errors=(verifier_state or {}).get('errors',0)
        failure_events=[]
        for finding in (rejected or {}).get('findings',[]):
            if finding.get('evidence',{}).get('verifier_error'):failure_events.append(finding['evidence']['verifier_error'])
        return_semantic=((result_refusal or {}).get('audit') or {}).get('r10_semantic') or {}
        if return_semantic.get('contextual_verifier_error'):failure_events.append(return_semantic['contextual_verifier_error'])
        results.append({'path':entry['path'],'suite':suite,'family':trace['attack_type'],'attacked':attacked,
            'archived_attack_success':trace.get('security') is True if attacked else None,'archive_error':trace.get('error'),
            'refused':bool(rejected or result_refusal),'call_refused':bool(rejected),'result_refused':bool(result_refusal),
            'refused_after_observed_injection':bool(first is not None and ((rejected and rejected['message_index']>first) or (result_refusal and result_refusal['message_index']>=first))),
            'validated_interception':bool(not unknown and not verifier_errors and not failure_events and first is not None and ((rejected and rejected['message_index']>first) or (result_refusal and result_refusal['message_index']>=first))),
            'first_injection':first,'first_refusal':rejected,'result_refusal':result_refusal,'alerted':any(d['action']=='ALERT' for d in decisions),
            'unknown_tools':unknown,'guard_errors':guard.stats['errors'],'verifier_state':verifier_state,'verifier_errors':verifier_errors,'verifier_failure_events':failure_events,'decisions':decisions})
        if hasattr(guard,'close'):guard.close()
        if len(results)%300==0:print(args.version,len(results),flush=True)
    rules.reset_knowledge_graph()
def score(rows):
    return {'n':len(rows),**{key:sum(bool(r[key]) for r in rows) for key in ['refused','call_refused','result_refused','alerted','validated_interception']},
        'unknown_tool_trajectories':sum(bool(r['unknown_tools']) for r in rows),'guard_errors':sum(r['guard_errors'] for r in rows),
        'archive_errors':sum(r['archive_error'] is not None for r in rows),'verifier_errors':sum(r.get('verifier_errors',0) for r in rows),'verifier_failure_trajectories':sum(bool(r.get('verifier_failure_events')) for r in rows)}
attacked=[r for r in results if r['attacked']];benign=[r for r in results if not r['attacked']]
assert len(attacked)==(0 if args.benign_only else protocol['expected_attack']) and len(benign)==protocol['expected_benign']
summary={'version':args.version,'development_only':args.development,'r11_action_intent':os.environ.get('GUARD_R11_ACTION')=='1','wall_s':time.perf_counter()-started,'attacked':score(attacked),'benign':score(benign),
    'historically_successful':score([r for r in attacked if r['archived_attack_success'] and r['archive_error'] is None]),
    'by_family':{f:score([r for r in attacked if r['family']==f and r['archived_attack_success'] and r['archive_error'] is None]) for f in protocol['attack_families']}}
summary['benign_only']=args.benign_only
summary['runtime_candidate']=protocol.get('candidate',args.version)
(destination/'cases.jsonl').write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in results),encoding='utf-8')
(destination/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True)
