"""Pinned inert dataset files, with Git blob integrity, no repository code execution."""
import hashlib,json
from pathlib import Path
import requests
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'07_修复验证/external_candidate_bipia'
protocol=json.loads((OUT/'protocol.json').read_text());tree=json.loads((OUT/'tree.json').read_text())['tree'];blobs={v['path']:v for v in tree}
manifest=[]
for name in protocol['files']:
    target=OUT/'raw'/name;target.parent.mkdir(parents=True,exist_ok=True)
    assert not target.exists(),'Dataset file already present; preserve the original download'
    response=requests.get(f"https://raw.githubusercontent.com/microsoft/BIPIA/{protocol['revision']}/{name}",timeout=60);response.raise_for_status();data=response.content
    assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blobs[name]['sha'],'Git blob mismatch'
    target.write_bytes(data);manifest.append({'path':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'git_blob_sha1':blobs[name]['sha']})
(OUT/'download_manifest.json').write_text(json.dumps(manifest,indent=2));print('Verified',len(manifest),'independent inert files')
