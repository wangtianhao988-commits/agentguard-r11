"""Freeze an independent text-return evaluation before downloading test content."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'07_修复验证/external_candidate_bipia'
assert not (OUT/'protocol.json').exists(),'Do not replace a frozen test protocol'
revision=(OUT/'revision.txt').read_text()
protocol={'version':'R11 independent classifier comparison','repository':'microsoft/BIPIA','revision':revision,
 'payload_unopened_at_freeze':True,'files':['benchmark/text_attack_test.json','benchmark/email/test.jsonl','benchmark/table/test.jsonl','LICENSE','NOTICE.md'],
 'selection':'All text test attacks, email+table, start+end+official seeded middle placement; one context per attack/domain chosen by SHA256 attack key modulo domain context count. All normal test contexts.',
 'seed':2023,'methods':{'R10':'R9 local authority+directive rule OR frozen MiniLM R10 head/windows',
 'Tiny':'Pinned published .9403395056724548 threshold; reference head-tail plus bounded token middle windows',
 'Wolf_L1':'Pinned Apache-2 L1 only; published .5 threshold; first2048-token development implementation, truncation explicitly reported'},
 'metric':'Document-text injection detection, not tool blocking, not model ASR, not competition qualification',
 'independence_limit':'Test not used in this project; public model pretraining/training overlap with public BIPIA cannot be excluded',
 'runtime_sources':{p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for part in ['collector','detector'] for p in sorted((ROOT/'track2'/part).glob('*.py'))},
 'model_assets':{p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for name in ['r10','r11_tiny','r11_wolf'] for p in sorted((ROOT/'track2/models'/name).rglob('*')) if p.is_file()}}
(OUT/'protocol.json').write_text(json.dumps(protocol,indent=2),encoding='utf-8')
print('Frozen independent BIPIA protocol',hashlib.sha256((OUT/'protocol.json').read_bytes()).hexdigest())
