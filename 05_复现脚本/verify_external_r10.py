"""Offline verify frozen inputs, outputs and guarded-source provenance."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'07_修复验证/external_r10'
protocol=json.loads((OUT/'protocol.json').read_text())
for version,root in [('R10',ROOT),('R9.1',ROOT/'baselines/R9_1')]:
    for path,sha in protocol['sources'][version].items():assert hashlib.sha256((root/path).read_bytes()).hexdigest()==sha
for path,sha in protocol['model_assets'].items():assert hashlib.sha256((ROOT/'track2/models/r10'/path).read_bytes()).hexdigest()==sha
manifest=json.loads((OUT/'download_manifest.json').read_text())
assert len(manifest['traces'])==protocol['expected_traces']
for row in manifest['traces']:
    raw=(OUT/'raw'/row['path']).read_bytes()
    assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
    assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==row['git_blob']
test=(OUT/'public_test.parquet').read_bytes();assert hashlib.sha256(test).hexdigest()==manifest['public_test']['sha256']
all_cases={}
for version in ['R9.1','R10']:
    rows=[json.loads(line) for line in (OUT/'results'/version/'cases.jsonl').read_text(encoding='utf-8').splitlines()]
    assert len(rows)==protocol['expected_traces'] and len({r['path'] for r in rows})==len(rows)
    assert sum(r['attacked'] for r in rows)==protocol['expected_attack'] and sum(not r['attacked'] for r in rows)==protocol['expected_benign']
    assert sum(r['guard_errors'] for r in rows)==0
    for row in rows:
        assert not row['validated_interception'] or (row['refused'] and row['first_injection'] is not None and not row['unknown_tools'])
        if row['result_refusal']:assert row['result_refusal']['audit']['action']=='DENY_RESULT'
    all_cases[version]={r['path']:r for r in rows}
assert set(all_cases['R9.1'])==set(all_cases['R10'])
successful=[path for path,row in all_cases['R10'].items() if row['attacked'] and row['archived_attack_success'] and row['archive_error'] is None]
paired={'n':len(successful),'baseline_only':0,'r10_only':0,'both':0,'neither':0}
for path in successful:
    a,b=[all_cases[v][path]['validated_interception'] for v in ['R9.1','R10']]
    paired['both' if a and b else 'baseline_only' if a else 'r10_only' if b else 'neither']+=1
(OUT/'paired_summary.json').write_text(json.dumps(paired,indent=2))
print(json.dumps({'frozen_sources_verified':True,'trace_hashes_verified':len(manifest['traces']),'paired_successful_traces':paired}))
