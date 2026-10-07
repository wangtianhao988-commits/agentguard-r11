"""Replay deployment result policies and finite intervention certificates.

Audit validation consumes observations only. It does not use attack labels to
decide whether a return is unsafe, or to alter the detector's decision.
"""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'detector'))
from intervention import ResultPolicies,minimum_intervention
from session import ToolCall, _unwrap_tool_result
from generalization import injection_evidence,views
from semantic_model import SemanticModel
MODEL=SemanticModel(Path(__file__).resolve().parents[1]/"models/r10")

def rows(directory,name):
    p=directory/(name+'.jsonl')
    return [json.loads(line) for line in p.read_text(encoding='utf-8').splitlines() if line.strip()] if p.exists() else []

def validate_plan(plan):
    assert plan and isinstance(plan.get('problem'),dict),'missing intervention problem'
    expected=minimum_intervention(plan['problem']['paths'],plan['problem']['candidates'])
    assert plan==expected,'certificate differs from exhaustive minimum-cost replay'

def validate_path(finding):
    evidence=finding.get('evidence',{})
    if 'graph' not in evidence: return False
    graph=evidence['graph'];path=evidence.get('path')
    ids={n['id'] for n in graph['nodes']}
    assert path and all(e in graph['edges'] for e in path),'unobserved graph edge'
    for index,edge in enumerate(path):
        assert edge['src'] in ids and edge['dst'] in ids
        if index: assert path[index-1]['dst']==edge['src'],'disconnected witness'
    if 'intervention' in evidence:validate_plan(evidence['intervention'])
    return True

def validate(directory):
    policies=ResultPolicies(json.loads((directory/'result_policy.json').read_text(encoding='utf-8')))
    original={r['rid']:r for r in rows(directory,'C_raw_response')}
    delivered={r['rid']:r for r in rows(directory,'C_response')}
    audits=rows(directory,'result_intervention');decisions=rows(directory,'guard_decision')
    assert len(original)==len(audits)==len({r['rid'] for r in audits}),'duplicate or missing raw results'
    post={r['rid']:r for r in decisions if r.get('point')=='result'}
    assert set(post)==set(original),'post-context decisions differ from interventions'
    for audit in audits:
        rid=audit['rid'];assert rid in original and rid in delivered
        raw=original[rid]['body']
        effective,expected=policies.project(ToolCall(audit['server'],audit['tool'],{}),raw)
        if 'r9_trust_boundary' in audit:
            proof=injection_evidence(_unwrap_tool_result(raw))
            assert proof is not None, 'R9 result lacks authority/directive conjunction'
            assert proof==audit['r9_trust_boundary'], 'R9 trust-boundary evidence mismatch'
            effective,expected=policies._deny(raw,'external result impersonates trusted instructions')
            expected['r9_trust_boundary']=proof
        if 'r10_semantic' in audit:
            proof=MODEL.inspect(views(_unwrap_tool_result(raw)))
            assert proof and proof['block'],'Frozen semantic head does not reject the recorded return'
            actual_proof=audit['r10_semantic']
            assert abs(proof['score']-actual_proof['score'])<1e-6,'Semantic score differs beyond CPU-platform tolerance'
            assert {k:v for k,v in proof.items() if k!='score'}=={k:v for k,v in actual_proof.items() if k!='score'},'Semantic window/model evidence mismatch'
            effective,expected=policies._deny(raw,'learned semantic injection score exceeds frozen threshold')
            expected['r10_semantic']=actual_proof
        assert expected is not None
        actual={k:audit[k] for k in expected}
        assert actual==expected,'result intervention policy replay mismatch'
        assert effective==delivered[rid]['body'],'delivered result was not approved projection/refusal'
        validate_plan(audit['plan'])
        assert post[rid]['action']=='BLOCK' and post[rid]['stage']=='pre-context'
    graphs=sum(validate_path(f) for r in decisions for f in r.get('findings',[]))
    return {'result_interventions':len(audits),'result_projections':sum(r['action']=='PROJECT' for r in audits),
        'result_refusals':sum(r['action']=='DENY_RESULT' for r in audits),'graph_witnesses_verified':graphs,
        'semantic_refusals_verified':sum('r10_semantic' in r for r in audits),'result_policy_replay':'exact','certificate_replay':'exhaustive finite minimum cost',
        'scope':'observed events; not proof of missing-event completeness or unknown future paths'}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--evidence',type=Path,required=True);p.add_argument('--json',type=Path)
    a=p.parse_args();result=validate(a.evidence)
    if a.json:a.json.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result))
