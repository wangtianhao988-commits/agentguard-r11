"""Verify frozen runtime/data and paired trace conclusions without running tools."""
import hashlib
import json
from pathlib import Path
P=Path(__file__).resolve().parents[1]; OUT=P/'07_修复验证'; ROOT=OUT/'AgentDojo_holdout'
protocol=json.loads((ROOT/'protocol.json').read_text())
checks=[]
for row in json.loads((ROOT/'download_manifest.json').read_text()):
    data=(ROOT/'raw'/row['path']).read_bytes()
    assert hashlib.sha256(data).hexdigest()==row['sha256']
    assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==row['git_blob_sha1']
checks.append('all 1385 source/data blobs match Git SHA-1 and SHA-256')
for version,root in [('R8',P/'baselines/R8'),('R9',P)]:
    for rel,digest in protocol[version+'_source_sha256'].items():
        assert hashlib.sha256((root/rel).read_bytes()).hexdigest()==digest
checks.append('R8 and R9.1 runtime sources match pre-download freeze')
cases={}
for version in ['R8','R9']:
    rows=[json.loads(line) for line in (ROOT/'results'/version/'cases.jsonl').read_text(encoding='utf-8').splitlines()]
    assert len(rows)==1355 and sum(r['attacked'] for r in rows)==1258
    assert all(r['guard_errors']==0 for r in rows)
    assert all(r['refused_after_observed_injection'] for r in rows if r['attacked'] and r['refused'])
    cases[version]={r['path']:r for r in rows}
assert cases['R8'].keys()==cases['R9'].keys()
successful=[key for key,r in cases['R8'].items() if r['archived_attack_success']]
assert len(successful)==251
gain=[k for k in successful if cases['R9'][k]['refused'] and not cases['R8'][k]['refused']]
loss=[k for k in successful if cases['R8'][k]['refused'] and not cases['R9'][k]['refused']]
assert len(gain)==6 and not loss
assert all(not r['refused'] and not r['alerted'] for r in cases['R9'].values() if not r['attacked'])
checks.append('six additional successful-trace interception opportunities; none lost; benign zero refuse/alert')
result={'checks':checks,'new_opportunities':gain,'lost_opportunities':loss,
        'scope':'historical prefixes; not closed-loop attack success or utility'}
(OUT/'external_verification_r9.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps({'checks':len(checks),'additional_opportunities':len(gain),'lost_opportunities':len(loss)}))
