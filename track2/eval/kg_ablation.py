"""Seeded synthetic mechanism challenge; not official or independent real attacks.

Counterexamples test exact grants, missing observations and missing resource
lineage. They are labelled relative to this stated threat model, not assertions
that an unobserved value is harmless in every real deployment.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import random
import sys
import time
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'track2/detector'), str(ROOT/'track2/collector')]
from knowledge_graph import KnowledgeGuard
from session import Session, ToolCall, register_tool
from task_policy import TaskPolicies
import rules

ALL = {'source','authorization','temporal','transform','memory'}

def generate(seed, count=32):
    rng = random.Random(seed)
    cases = []
    families = ['direct','encoded','cross_session','shared_resource','unauthorized',
                'public_summary','approved_export','unrelated_principal','wrong_resource','documentation']
    for family in families:
        for index in range(count):
            secret = 'fixture-'+''.join(rng.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(22))+'+/'
            identifier = family+'-'+str(index)
            server = 'svc-'+str(rng.randrange(1000000))
            actors = ['subject-'+str(rng.randrange(1000000)), 'subject-other-'+str(rng.randrange(1000000))]
            register_tool(server,'read',{},'Return a report',{'fs_read'})
            register_tool(server,'save',{},'Store a document',{'fs_write'})
            register_tool(server,'load',{},'Return a stored document',{'fs_read'})
            register_tool(server,'relay',{},'Transmit via HTTP',{'net'})
            transform = [lambda s:s, lambda s:base64.b64encode(s.encode()).decode(), lambda s:s.encode().hex(), lambda s:quote(s,safe='')]
            outgoing = secret
            if family=='encoded': outgoing=transform[1+index%3](secret)
            if family=='cross_session': outgoing=transform[1](secret)
            if family=='shared_resource': outgoing=transform[2](secret)
            if family in {'public_summary','unauthorized'}: outgoing='Keys were rotated this week.'
            result = {'api_key':secret}
            if family=='documentation': result={'api_key_docs':secret, 'secretary':'ordinary-person-name'}
            operations = [{'principal':actors[0],'session':identifier+'-a','tool':'read',
                           'arguments':{'path':'/reports/item.txt'},'result':result}]
            sink_actor, sink_session = actors[0], identifier+'-a'
            if family in {'cross_session','approved_export'}: sink_session=identifier+'-b'
            if family in {'shared_resource','wrong_resource'}:
                operations += [
                    {'principal':actors[0],'session':identifier+'-a','tool':'save',
                     'arguments':{'scope':'shared','key':'incident','opaque':secret},'result':{'saved':True}},
                    {'principal':actors[1],'session':identifier+'-b','tool':'load',
                     'arguments':{'scope':'shared','key':'incident' if family=='shared_resource' else 'different'},
                     'result':{'text':secret}}]
                sink_actor, sink_session = actors[1], identifier+'-b'
            if family=='unrelated_principal': sink_actor, sink_session=actors[1], identifier+'-b'
            operation = {'principal':sink_actor,'session':sink_session,'tool':'relay',
                         'arguments':{'opaque':outgoing},'result':{'sent':True}}
            if family in {'approved_export','unauthorized'}:
                permissions = [{'server':server,'tool':'relay','arguments':{'opaque':[outgoing]}}] if family=='approved_export' else []
                policy = TaskPolicies({'version':1,'tasks':[{'id':'task','principals':[sink_actor],'permissions':permissions}]})
                operation['binding'] = policy.bind(sink_actor,'task')
            operations.append(operation)
            cases.append({'id':identifier,'family':family,'positive':family in families[:5],
                          'server':server,'operations':operations})
    return cases

def evaluate(case, mode):
    components = ALL if mode in {'graph','combined'} else ALL-{mode.removeprefix('without_')}
    engine = KnowledgeGuard(components)
    rules.clear_cross_session_state()
    sessions, flagged = {}, False
    witnesses = []
    for op in case['operations']:
        call = ToolCall(case['server'], op['tool'], copy.deepcopy(op['arguments']),
                        trusted_task_policy=copy.deepcopy(op.get('binding')))
        inferred = engine.check(op['principal'], op['session'], call) if mode!='baseline' else []
        session = sessions.setdefault(op['session'], Session(op['session'], identity={'sub':op['principal']}))
        session.calls.append(call)
        base = rules.analyse_session(session) if mode in {'baseline','combined'} else []
        blocked = bool(inferred) or any(f.severity=='BLOCK' for f in base)
        flagged |= bool(inferred) or any(f.severity in {'ALERT','BLOCK'} for f in base)
        witnesses.extend(inferred)
        if not blocked:
            call.result, call.ok = copy.deepcopy(op['result']), True
            if mode!='baseline': engine.observe(op['principal'],op['session'],call,call.result)
        if mode in {'baseline','combined'}: rules.remember_session(session)
    return flagged, witnesses

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,default=ROOT/'07_修复验证/R7_kg_ablation')
    args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=True)
    os.environ['GUARD_KG']='0'  # combined uses its explicitly controlled engine
    cases=[]
    for split,seed in [('development',73021),('holdout',99473)]:
        for case in generate(seed): case['split']=split; cases.append(case)
    corpus=''.join(json.dumps(case,ensure_ascii=False)+'\n' for case in cases)
    (args.output/'cases.jsonl').write_text(corpus,encoding='utf-8')
    results=[]
    for mode in ['baseline','graph','combined','without_source','without_authorization',
                 'without_temporal','without_transform','without_memory']:
        for split in ['development','holdout']:
            stats={'tp':0,'fp':0,'fn':0,'tn':0}
            errors=[]; examples=[]; started=time.perf_counter()
            for case in [c for c in cases if c['split']==split]:
                hit,witness=evaluate(case,mode)
                key=('tp' if hit else 'fn') if case['positive'] else ('fp' if hit else 'tn')
                stats[key]+=1
                if key in {'fp','fn'}: errors.append(case['id'])
                if witness and not any(e['family']==case['family'] for e in examples):
                    examples.append({'case':case['id'],'family':case['family'],'witness':witness[0]})
            results.append({'mode':mode,'split':split,**stats,
                'recall':stats['tp']/max(1,stats['tp']+stats['fn']),
                'false_positive_rate':stats['fp']/max(1,stats['fp']+stats['tn']),
                'wall_s':time.perf_counter()-started,'errors':errors,'examples':examples})
    summary={'scope':'synthetic mechanism positives/controls; not official or independently collected real attacks',
             'cases':len(cases),'seeds':[73021,99473],'corpus_sha256':hashlib.sha256(corpus.encode()).hexdigest(),
             'results':results,'ablation_scope':'graph-only removals; combined preserves independent R6 findings'}
    (args.output/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
    for row in results: print(row['split'],row['mode'],{k:row[k] for k in ['tp','fp','fn','tn']})
    assert all(r['fn']==0 and r['fp']==0 for r in results if r['mode'] in {'graph','combined'})

if __name__=='__main__': main()
