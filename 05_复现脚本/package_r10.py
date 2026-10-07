"""Reviewable immutable R10; preserve failures, exclude private mutable state."""
import hashlib,json,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'07_修复验证'
def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
summary=json.loads((OUT/'qualification_summary_r10.json').read_text(encoding='utf-8'))
assert summary['regressions']==126 and all(r['exit_code']==0 for r in summary['verification']['checks'])
assert summary['external_95pct_achieved'] is False and summary['all_competition_requirements_achieved'] is False
assert (OUT/'R10_runtime_snapshot.json').exists() and (OUT/'R10_restart_check.json').exists()
unchanged=[]
for name,sha in [
    ('网络安全创新大赛题目2_交付包_组合增强版R8_20261004.zip','96c9155eca6179e11842211cd0dd743aa9de60c255ae4d3ba8bc12cb0dc58ff8'),
    ('网络安全创新大赛题目2_送审材料_组合增强版R8_20261004.zip','20e0ce98a7f08f837b41182d0a3a5d0802966560a7910d8ae10b034736f9335c'),
    ('网络安全创新大赛题目2_交付包_泛化增强版R9_1_20261004.zip','9ebfc01a81bfc362c056945c73ef089732425bd9c980ab21b1def9d06d741564')]:
    assert digest(Path('C:/Users/wangth/Desktop')/name)==sha
    unchanged.append({'archive':name,'sha256':sha})
def include(path):
    rel=path.relative_to(ROOT);parts=rel.parts
    if any(part in {'__pycache__','.venv','.git','09_运行状态','state','pdf_qa','node_modules'} for part in parts):return False
    if path.suffix in {'.pyc','.sqlite','.db'} or path.name.endswith(('.sqlite-wal','.sqlite-shm','.db-wal','.db-shm')):return False
    if parts[0]=='01_交付文档':return path.name.startswith('R10_')
    if parts[:4]==('_scratch','competition','agentrange','evidence'):return path.name=='inventory.json'
    if parts[:2]==('07_修复验证','onnx_optimization') and path.suffix=='.onnx':return False
    return path.name not in {'artifact_manifest_r10.json','delivery_r10_manifest.json'}
files=[p for p in ROOT.rglob('*') if p.is_file() and include(p)]
manifest=[{'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':digest(p)} for p in sorted(files)]
(OUT/'artifact_manifest_r10.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
destination=Path('C:/Users/wangth/Desktop/网络安全创新大赛题目2_交付包_全面增强版R10_20261004.zip')
assert not destination.exists(),'Never overwrite a delivered version'
with zipfile.ZipFile(destination,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
    for file in sorted(files):archive.write(file,ROOT.name+'/'+file.relative_to(ROOT).as_posix())
    archive.write(OUT/'artifact_manifest_r10.json',ROOT.name+'/07_修复验证/artifact_manifest_r10.json')
with zipfile.ZipFile(destination) as archive:
    assert archive.testzip() is None
    for row in manifest:assert hashlib.sha256(archive.read(ROOT.name+'/'+row['path'])).hexdigest()==row['sha256']
    assert not any('/09_运行状态/' in name or '/state/' in name or '.sqlite' in name or '/.git/' in name for name in archive.namelist())
result={'path':str(destination),'bytes':destination.stat().st_size,'sha256':digest(destination),'manifest_files':len(manifest),
    'previous_archives_unchanged':unchanged,'private_state_shipped':False,'external_95pct_achieved':False,'fully_qualified':False}
(OUT/'delivery_r10_manifest.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(result,ensure_ascii=False))
