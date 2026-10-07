"""Package R8 separately, verifying frozen inputs and immutable R6 first."""
from pathlib import Path
import hashlib
import json
import zipfile

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'07_修复验证'
OLD=ROOT.parent/'AgentGuard_修正版'
def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()
summary=json.loads((OUT/'qualification_summary_r8.json').read_text(encoding='utf-8'))
assert summary['regressions']==95 and all(r['status']=='completed' for r in summary['verification'])
cpu=json.loads((OUT/'R8_cpu_qualified/measurement.json').read_text(encoding='utf-8'))
assert cpu['status']=='completed'
for field in ['source_sha256','driver_source_sha256']:
    for path,sha in cpu[field].items(): assert digest(ROOT/path)==sha
for path in [OLD/'07_修复验证/final_source_manifest_r6.json',OUT/'frozen_evidence_manifest.json']:
    base=OLD if path.is_relative_to(OLD) else ROOT
    for row in json.loads(path.read_text(encoding='utf-8')):
        assert digest(base/row['path'])==row['sha256']
provenance=json.loads((OUT/'R4_official_provenance.json').read_text(encoding='utf-8'))
for row in provenance['official_files']:
    assert digest(ROOT/'06_赛题与第三方/官方靶场原包/agentrange'/row['path'])==row['sha256']
for name,sha in [
    ('网络安全创新大赛题目2_交付包_提升版R6_20261004.zip','7c473b62ef664ccfd0311c2f2db8a9cc35743aff8af71d7630fe7da7fb384f4f'),
    ('网络安全创新大赛题目2_送审材料_提升版R6_20261004.zip','11f89743e15cecbd6d305825134332754c9721a79d0d37f514ba49fab1b17ee9')]:
    assert digest(Path('C:/Users/wangth/Desktop')/name)==sha
for name,sha in [
    ('网络安全创新大赛题目2_交付包_知识图谱增强版R7_20261004.zip','137843ec63333ca2131c0347b0769694fad5c6a3c5ea9de35d76ffea18d9a610'),
    ('网络安全创新大赛题目2_送审材料_知识图谱增强版R7_20261004.zip','b5308dcc24e272c955dbe6f3409efd71b2f0c39b5ccf15812ab77258e82c4056')]:
    assert digest(Path('C:/Users/wangth/Desktop')/name)==sha
r7=ROOT.parent/'AgentGuard_知识图谱增强版R7'
for row in json.loads((r7/'07_修复验证/final_source_manifest_r7.json').read_text(encoding='utf-8')):
    assert digest(r7/row['path'])==row['sha256']


dependencies={'R3_native_guard_40eps/compose.native.json','R3诊断/Dockerfile.authfix',
    'R4_official_provenance.json','R6_static_inventory_final.json','frozen_evidence_manifest.json',
    'qualification_summary_r6.json','qualification_summary_r8.json','final_source_manifest_r8.json'}
def include(path):
    rel=path.relative_to(ROOT); parts=rel.parts
    if any(p in {'__pycache__','.venv','pdf_qa','08_历史材料_不提交','09_运行状态','state'} for p in parts): return False
    if path.suffix in {'.pyc','.sqlite','.db'} or path.name.endswith(('.sqlite-wal','.sqlite-shm','.db-wal','.db-shm')) or '修改前备份' in path.name: return False
    if parts[0]=='01_交付文档': return path.name.startswith('R8_')
    if parts[0]=='07_修复验证':
        return parts[1].startswith('R8_') or '/'.join(parts[1:]) in dependencies
    if parts[:4]==('_scratch','competition','agentrange','evidence'):
        return path.name=='inventory.json'
    return True

sourcefiles=[p for p in ROOT.rglob('*') if p.is_file() and include(p) and
    (p.relative_to(ROOT).parts[0] in {'track2','05_复现脚本','01_交付文档','_scratch','06_赛题与第三方'} or
     p.name in {'README.md','开发修复记录.md'})]
manifest=[{'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':digest(p)} for p in sorted(sourcefiles)]
(OUT/'final_source_manifest_r8.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
files=[p for p in ROOT.rglob('*') if p.is_file() and include(p)]
results=[]; prefix='AgentGuard_组合增强版R8'
for kind in ['交付包','送审材料']:
    selected=files if kind=='交付包' else [p for p in files if p.relative_to(ROOT).parts[0] in {'01_交付文档','07_修复验证'}]
    destination=Path('C:/Users/wangth/Desktop')/f'网络安全创新大赛题目2_{kind}_组合增强版R8_20261004.zip'
    assert not destination.exists(),'Refusing overwrite'
    with zipfile.ZipFile(destination,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
        for path in sorted(selected): archive.write(path,prefix+'/'+path.relative_to(ROOT).as_posix())
        if kind=='送审材料':
            archive.writestr(prefix+'/送审说明.md','R8 当前报告和可审计证据。可运行源代码、Docker 构建与完整复现输入位于同名 R8 交付包。R3/R4/R6 文件只作为历史基线或部署依赖，不代表 R8 成绩。\n')
    with zipfile.ZipFile(destination) as archive:
        assert archive.testzip() is None
        assert prefix+'/01_交付文档/R8_技术说明书.pdf' in archive.namelist()
        if kind=='交付包':
            for row in manifest:
                assert hashlib.sha256(archive.read(prefix+'/'+row['path'])).hexdigest()==row['sha256']
            for required in ['track2/detector/knowledge_graph.py','05_复现脚本/deploy_r3.py',
                '05_复现脚本/verify_frozen_r8.py','README.md']:
                assert prefix+'/'+required in archive.namelist()
    results.append({'path':str(destination),'bytes':destination.stat().st_size,'sha256':digest(destination),'files':len(selected)})
(OUT/'delivery_r8_manifest.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps({'archives':results,'source_manifest_files':len(manifest),'official_files_verified':len(provenance['official_files']),
    'R6_R7_archives_and_sources_unchanged':True},ensure_ascii=False))
