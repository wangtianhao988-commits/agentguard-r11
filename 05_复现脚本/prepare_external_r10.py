"""Freeze before downloading any new test payload; never replace a protocol."""
import hashlib,json,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OLD=ROOT.parent/'R8_外部泛化_AgentDojo_20261004'
OUT=ROOT/'07_修复验证/external_r10'
OUT.mkdir(exist_ok=True)
assert not (OUT/'protocol.json').exists(),'Frozen protocol already exists'
tree=json.loads((OLD/'tree.json').read_text())['tree']
model='meta-llama_Llama-3.3-70B-Instruct';families=['direct','ignore_previous','important_instructions','none']
selection=[r for r in tree if r['type']=='blob' and r['path'].startswith('runs/'+model+'/') and r['path'].endswith('.json') and r['path'].split('/')[4] in families]
assert len(selection)==2979
for source in (OLD/'raw/src').rglob('*.py'):
    dest=OUT/'raw'/source.relative_to(OLD/'raw');dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,dest)
shutil.copy2(OLD/'replay.py',OUT/'metadata_reader.py')
protocol={'candidate':'R10','baseline':'R9.1','commit':'089ed468cf3ed0322acc66b0211f26d9d90dbf60','model':model,
    'attack_families':families[:-1],'expected_attack':2847,'expected_benign':132,'expected_traces':2979,
    'metric':'Historical trace interception opportunities; not closed-loop model attack-success reduction',
    'test_payload_unopened_at_freeze':True,'public_text_test':'deepset/prompt-injections pinned public test, not calibration',
    'metadata':'Published v1 tools/schema AST; newer unknown tools reported, not counted as validated attack interception',
    'limits':['New model archives, same suite domains','No archived tool implementations or attacker expressions executed',
        'Source metadata may differ from archived runtime','No generative model API used','Refused benign tasks are utility failures'],
    'sources':{},'model_assets':{}}
for version,root in [('R10',ROOT),('R9.1',ROOT/'baselines/R9_1')]:
    protocol['sources'][version]={p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
        for part in ['collector','detector'] for p in sorted((root/'track2'/part).glob('*.py'))}
protocol['model_assets']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'track2/models/r10').iterdir() if p.is_file()}
(OUT/'selection.json').write_text(json.dumps(selection,indent=2))
(OUT/'protocol.json').write_text(json.dumps(protocol,indent=2))
print('Frozen R10 sources/model before opening',len(selection),'new-model trajectories')
