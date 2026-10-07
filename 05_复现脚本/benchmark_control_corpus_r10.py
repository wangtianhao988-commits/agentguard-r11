"""Corpus-powered fixed-plan control invariant; no generative-model ASR claim."""
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'07_修复验证/external_r10'
sys.path.insert(0,str(ROOT/'track2/detector'))
from trusted_plan import ControlPlans
from controlled_executor import ControlledExecutor
policy={'version':1,'plans':[{'id':'report','principals':['alice'],'inputs':{},'steps':[
    {'id':'read','server':'docs','tool':'read','arguments':{},'result_labels':['untrusted']},
    {'id':'deliver','server':'mail','tool':'send','arguments':{'to':{'literal':'approved@example.test'},'body':{'result':['read','text']}},'data_arguments':['body'],'accept_labels':['untrusted'],'result_labels':['untrusted']}]}]}
executor=ControlledExecutor(ControlPlans(policy));texts={}
for entry in json.loads((OUT/'selection.json').read_text()):
    trace=json.loads((OUT/'raw'/entry['path']).read_text(encoding='utf-8'))
    for text in trace.get('injections',{}).values():
        if isinstance(text,str):texts.setdefault(hashlib.sha256(text.encode()).hexdigest(),text)
results=[]
for digest,text in texts.items():
    calls=[]
    def transport(server,name,args):
        calls.append({'server':server,'tool':name,'arguments':args})
        return {'text':text} if name=='read' else {'sent':True}
    result=executor.execute('alice','report',{},transport)
    assert result['completed'] and [c['tool'] for c in calls]==['read','send']
    assert calls[1]['arguments']=={'to':'approved@example.test','body':text}
    results.append({'payload_sha256':digest,'completed':True,'fixed_destination_unchanged':True,'unexpected_calls':0})
summary={'distinct_archived_payloads':len(results),'unauthorized_destinations':0,'unexpected_calls':0,'approved_plan_completed':len(results),
    'scope':'Archived payloads substituted into one synthetic fixed workflow; no LLM or real email/tool execution',
    'does_not_prevent_corrupted_body_content':True,'not_external_agent_detection_recall':True,'cases':results}
(ROOT/'07_修复验证/R10_control_corpus.json').write_text(json.dumps(summary,indent=2));print(json.dumps({k:v for k,v in summary.items() if k!='cases'}))
