"""Nonempty business ledger with declared releases; not an external benchmark."""
import base64,hashlib,json,os,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'track2/detector'),str(ROOT/'track2/collector'),str(ROOT/'track2/eval')]
from session import register_tool
from security_graph import SecurityGraph
from inline_guard import InlineGuard
from r8_audit import validate_path
import rules
os.environ.update(GUARD_R10='1',GUARD_R10_MODEL_PATH=str(ROOT/'track2/models/r10'),GUARD_R8='1',GUARD_KG='1')
policy={'version':1,'sources':[],'release':[{'principal':'alice','server':'docs','tool':'send','label':'sensitive-schema-field','destinations':['doctor@hospital.test']}]}
for name,caps,description in [('read',{'fs_read'},'Read patient record'),('send',{'net'},'Send message')]:register_tool('docs',name,{},description,caps)
with tempfile.TemporaryDirectory(prefix='r10_business_') as state:
    state=Path(state);(state/'policy.json').write_text(json.dumps(policy));os.environ.update(GUARD_R10_DATA_POLICY_PATH=str(state/'policy.json'),GUARD_GRAPH_STATE_PATH=str(state/'r8.sqlite'))
    rules.reset_knowledge_graph();rules._R8_INVENTORY={'asset_graph':{'assets':[{'kind':'tool','name':'docs.'+name,'attributes':{}} for name in ['read','send']]}};rules._R8_RESULT_POLICY={'version':1,'tools':[]}
    guard=InlineGuard();cases=[];started=time.perf_counter();cpu=time.process_time()
    texts=['Patient diagnosis report for record '+hashlib.sha256(str(i).encode()).hexdigest()+' with confidential clinical observations and prescribed care.' for i in range(12)]
    for i,text in enumerate(texts):
        sid=f'read-{i}';s=guard._session(sid);s.identity={'sub':'alice','scope':{}};s.prompt='Read the patient record'
        assert not guard.check_tool_call(sid,'docs','read',{},sid).blocked
        delivered,audit=guard.observe_tool_result(sid,sid,{'id':sid,'result':{'diagnosis':text}})
        assert audit is None,'Business data must remain readable'
    for repeat in range(5):
        for i,text in enumerate(texts):
            for kind,value in [('identity',text),('base64',base64.b64encode(text.encode()).decode()),('hex',text.encode().hex()),('partial',text[:64])]:
                for malicious,to in [(False,'doctor@hospital.test'),(True,'outside@example.test')]:
                    sid=f'{repeat}-{i}-{kind}-{malicious}';s=guard._session(sid);s.identity={'sub':'alice','scope':{}};s.prompt='Read patient records and send a summary to doctor@hospital.test'
                    before=time.perf_counter();decision=guard.check_tool_call(sid,'docs','send',{'to':to,'body':value},sid)
                    witness=[f.to_json() for f in decision.findings if f.rule_id=='r10-business-flow']
                    for finding in witness:assert validate_path(finding)
                    cases.append({'malicious':malicious,'encoding':kind,'refused':decision.blocked,'r10_witnesses':len(witness),'wall_ms':(time.perf_counter()-before)*1000})
                    assert decision.blocked==malicious,'Declared release or observed leak decision mismatch'
    prior=guard.snapshot()['r10']['business_flow'];guard.close();guard=InlineGuard();restored=guard.snapshot()['r10']['business_flow']
    assert restored['restored'] and restored['sources']==12 and prior['namespace']==restored['namespace'];guard.close();rules.reset_knowledge_graph()
    result={'scope':'Synthetic native InlineGuard stress, declared release policy, no real MCP/model planning; nonempty private ledger',
        'n':len(cases),'attacks':sum(r['malicious'] for r in cases),'false_positives':sum(r['refused'] and not r['malicious'] for r in cases),
        'missed':sum(not r['refused'] and r['malicious'] for r in cases),'max_decision_ms':max(r['wall_ms'] for r in cases),
        'cpu_s':time.process_time()-cpu,'wall_s':time.perf_counter()-started,'restored_sources':restored['sources'],'private_state_shipped':False,'cases':cases}
(ROOT/'07_修复验证/R10_business_benchmark.json').write_text(json.dumps(result,indent=2));print(json.dumps({k:v for k,v in result.items() if k!='cases'}))
