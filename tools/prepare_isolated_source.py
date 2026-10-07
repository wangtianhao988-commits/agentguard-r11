"""Preserve R11; copy its frozen runtime and manifests into an isolated root."""
import hashlib,json,shutil,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; R11=ROOT.parent/'AgentGuard_达标攻坚版R11'
DATA=R11/'07_修复验证/external_r11_gemini'; OUT=ROOT/'07_修复验证/external_r11_gemini'
OUT.mkdir(parents=True,exist_ok=True);(ROOT/'reports').mkdir(exist_ok=True)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
protocol=json.loads((DATA/'protocol.json').read_text())
original={str(p):sha(p) for p in R11.rglob('*.py')}
for area in ['track2/collector','track2/detector']:
    for p in (R11/area).glob('*.py'):
        dest=ROOT/p.relative_to(R11);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dest)
for rel,h in protocol['sources']['R10'].items():
    src=DATA/'source_snapshot'/rel;assert sha(src)==h
    dest=ROOT/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dest)
for rel in ['protocol.json','protocol.sha256','selection.json','download_manifest.json']:
    shutil.copy2(DATA/rel,OUT/rel)
for name in protocol['model_assets_by_version']['R10']:
    dest=ROOT/'track2/models/r10'/name;dest.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(R11/'track2/models/r10'/name,dest)
for rel,h in protocol['r11_model_assets'].items():
    dest=ROOT/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(R11/rel,dest);assert sha(dest)==h
report={'original_python_sha256':original,'original_protocol_sha256':sha(DATA/'protocol.json'),
        'original_frozen_cases_sha256':sha(DATA/'results/R11_frozen/cases.jsonl'),
        'copied_frozen_source_count':len(protocol['sources']['R10']),
        'evaluator_unmodified_sha256':sha(ROOT/'05_复现脚本/evaluate_external_r10.py')}
(ROOT/'reports/r12d_original_preservation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
(ROOT/'.gitignore').write_text('__pycache__/\n*.pyc\ntrack2/models/\n07_修复验证/\n',encoding='utf-8')
subprocess.run(['git','init','-b','codex/r12d-minimal-boundary',str(ROOT)],check=True,capture_output=True)
subprocess.run(['git','-C',str(ROOT),'add','.'],check=True)
subprocess.run(['git','-C',str(ROOT),'commit','-m','chore: preserve frozen R11 runtime for isolated boundary experiment'],check=True,capture_output=True)
print('Isolated baseline committed; evaluator and original R11 preserved.')
