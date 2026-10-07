"""Read-only provenance verification, no detector tuning or attack execution."""
import argparse,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'07_修复验证/external_r11_gemini'
parser=argparse.ArgumentParser()
parser.add_argument('--source-snapshot', action='store_true', help='Verify preserved frozen code rather than the evolving working tree')
args=parser.parse_args()
protocol=json.loads((OUT/'protocol.json').read_text());expected=(OUT/'protocol.sha256').read_text().strip()
assert hashlib.sha256((OUT/'protocol.json').read_bytes()).hexdigest()==expected
for path,digest in protocol['sources']['R10'].items():
    base=OUT/'source_snapshot' if args.source_snapshot else ROOT
    assert hashlib.sha256((base/path).read_bytes()).hexdigest()==digest,path
for path,digest in protocol['r11_model_assets'].items():assert hashlib.sha256((ROOT/path).read_bytes()).hexdigest()==digest,path
for path,digest in protocol['model_assets_by_version']['R10'].items():assert hashlib.sha256((ROOT/'track2/models/r10'/path).read_bytes()).hexdigest()==digest,path
selection=json.loads((OUT/'selection.json').read_text());manifest=json.loads((OUT/'download_manifest.json').read_text())['traces'];index={r['path']:r for r in manifest}
assert len(index)==len(selection)==protocol['expected_traces']
for row in selection:
    data=(OUT/'raw'/row['path']).read_bytes()
    assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==row['sha']
    assert hashlib.sha256(data).hexdigest()==index[row['path']]['sha256']
model=ROOT/'07_修复验证/model_candidates/qwen3_4b/Qwen3-4B-Q4_K_M.gguf'
with model.open('rb') as stream:assert hashlib.file_digest(stream,'sha256').hexdigest()==protocol['verifier_model_sha256']
print('Frozen implementation, both model assets and all 1081 pinned archive objects verified')
