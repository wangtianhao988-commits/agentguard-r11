"""Download the adopted public model only, with fixed revision/size/SHA.

No API token, remote Python, pickle, paid endpoint or model training is involved.
Existing verified weights are reused. Partial files are not accepted as models.
"""
import hashlib,json
from pathlib import Path
import requests
ROOT=Path(__file__).resolve().parents[1]
REPO='Qwen/Qwen3-4B-GGUF';REVISION='bc640142c66e1fdd12af0bd68f40445458f3869b'
NAME='Qwen3-4B-Q4_K_M.gguf';SIZE=2497280256
SHA='7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5'
destination=ROOT/'07_修复验证/model_candidates/qwen3_4b';destination.mkdir(parents=True,exist_ok=True)
target=destination/NAME
if not target.exists():
    partial=target.with_suffix(target.suffix+'.partial')
    with requests.get(f'https://huggingface.co/{REPO}/resolve/{REVISION}/{NAME}',stream=True,timeout=(30,120)) as response:
        response.raise_for_status();count=0
        with partial.open('wb') as output:
            for chunk in response.iter_content(1024*1024):
                count+=len(chunk)
                if count>SIZE:raise ValueError('Model exceeds pinned size')
                output.write(chunk)
                if count%(128*1024*1024)==0:print('Downloaded MiB',count//(1024*1024),flush=True)
    with partial.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    if partial.stat().st_size!=SIZE or digest!=SHA:raise ValueError('Model size/SHA mismatch; partial file not adopted')
    partial.replace(target)
with target.open('rb') as stream:assert hashlib.file_digest(stream,'sha256').hexdigest()==SHA
assert target.stat().st_size==SIZE
manifest={'repository':REPO,'revision':REVISION,'files':[{'path':NAME,'bytes':SIZE,'sha256':SHA}]}
for name in ['LICENSE','README.md']:
    path=destination/name
    if not path.exists():
        response=requests.get(f'https://huggingface.co/{REPO}/resolve/{REVISION}/{name}',timeout=30);response.raise_for_status();path.write_bytes(response.content)
    manifest['files'].append({'path':name,'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
(destination/'provenance_download.json').write_text(json.dumps(manifest,indent=2))
print('Pinned local model verified; see deploy_local_verifier.py')
