"""Immutable R9.1 delivery with all data, failed-candidate evidence and hashes."""
import hashlib
import json
import zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'07_修复验证'
def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
summary=json.loads((OUT/'qualification_summary_r9.json').read_text(encoding='utf-8'))
assert summary['regressions']==103 and all(r['exit_code']==0 for r in summary['review_checks'])
cpu=json.loads((OUT/'R9_1_cpu_verified/measurement.json').read_text())
assert cpu['status']=='completed' and len(cpu['pairs'])==1
for field in ['source_sha256','driver_source_sha256']:
    for path,sha in cpu[field].items():assert digest(ROOT/path)==sha
for version,base in [('R8',ROOT/'baselines/R8'),('R9',ROOT)]:
    protocol=json.loads((OUT/'AgentDojo_holdout/protocol.json').read_text())
    for path,sha in protocol[version+'_source_sha256'].items():assert digest(base/path)==sha
unchanged=[]
for name,sha in [
    ('网络安全创新大赛题目2_交付包_组合增强版R8_20261004.zip','96c9155eca6179e11842211cd0dd743aa9de60c255ae4d3ba8bc12cb0dc58ff8'),
    ('网络安全创新大赛题目2_送审材料_组合增强版R8_20261004.zip','20e0ce98a7f08f837b41182d0a3a5d0802966560a7910d8ae10b034736f9335c')]:
    assert digest(Path('C:/Users/wangth/Desktop')/name)==sha
    unchanged.append({'archive':name,'sha256':sha})
def include(path):
    rel=path.relative_to(ROOT);parts=rel.parts
    if any(part in {'__pycache__','.venv','09_运行状态','state','pdf_qa'} for part in parts):return False
    if path.suffix in {'.pyc','.sqlite','.db'} or path.name.endswith(('.sqlite-wal','.sqlite-shm','.db-wal','.db-shm')):return False
    if parts[0]=='01_交付文档':return path.name.startswith('R9_1_')
    if parts[:4]==('_scratch','competition','agentrange','evidence'):return path.name=='inventory.json'
    return path.name not in {'artifact_manifest_r9.json','delivery_r9_manifest.json'}
files=[p for p in ROOT.rglob('*') if p.is_file() and include(p)]
manifest=[{'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':digest(p)} for p in sorted(files)]
(OUT/'artifact_manifest_r9.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
destination=Path('C:/Users/wangth/Desktop/网络安全创新大赛题目2_交付包_泛化增强版R9_1_20261004.zip')
assert not destination.exists(),'Refusing to overwrite an artifact'
prefix=ROOT.name
with zipfile.ZipFile(destination,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
    for path in sorted(files):archive.write(path,prefix+'/'+path.relative_to(ROOT).as_posix())
    archive.write(OUT/'artifact_manifest_r9.json',prefix+'/07_修复验证/artifact_manifest_r9.json')
with zipfile.ZipFile(destination) as archive:
    assert archive.testzip() is None
    for row in manifest:assert hashlib.sha256(archive.read(prefix+'/'+row['path'])).hexdigest()==row['sha256']
    assert not any('/09_运行状态/' in name or '/state/' in name or '.sqlite' in name for name in archive.namelist())
result={'path':str(destination),'bytes':destination.stat().st_size,'sha256':digest(destination),
        'manifest_files':len(manifest),'R8_archives_unchanged':unchanged,'private_state_shipped':False,
        'competition_generalization_95pct_achieved':False}
(OUT/'delivery_r9_manifest.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(result,ensure_ascii=False))
