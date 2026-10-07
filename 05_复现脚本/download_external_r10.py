"""Download pinned, pre-selected inert JSON traces and public semantic test."""
import concurrent.futures,hashlib,json,time,threading
from pathlib import Path
import requests
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'07_修复验证/external_r10'
protocol=json.loads((OUT/'protocol.json').read_text());selection=json.loads((OUT/'selection.json').read_text())
local=threading.local()
def fetch(row):
    if not hasattr(local,'session'):local.session=requests.Session()
    path=OUT/'raw'/row['path'];path.parent.mkdir(parents=True,exist_ok=True)
    url='https://raw.githubusercontent.com/ethz-spylab/agentdojo/'+protocol['commit']+'/'+row['path']
    if not path.exists():
        for attempt in range(5):
            try:
                response=local.session.get(url,timeout=20);response.raise_for_status();payload=response.content
                assert hashlib.sha1(b'blob '+str(len(payload)).encode()+b'\0'+payload).hexdigest()==row['sha'],'Git blob mismatch'
                json.loads(payload);path.write_bytes(payload);break
            except Exception:
                if attempt==4:raise
                time.sleep(attempt+1)
    payload=path.read_bytes()
    assert hashlib.sha1(b'blob '+str(len(payload)).encode()+b'\0'+payload).hexdigest()==row['sha']
    return {'path':row['path'],'bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest(),'git_blob':row['sha']}
manifest=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
    jobs=[pool.submit(fetch,row) for row in selection]
    for job in concurrent.futures.as_completed(jobs):
        item=job.result()
        manifest.append(item)
        if len(manifest)%300==0:print('Downloaded',len(manifest),flush=True)
metadata=json.loads((ROOT/'07_修复验证/semantic_training/datasets_metadata.json').read_text())
url='https://huggingface.co/datasets/deepset/prompt-injections/resolve/'+metadata['sha']+'/data/test-00000-of-00001-701d16158af87368.parquet'
response=requests.get(url,timeout=60);response.raise_for_status()
(OUT/'public_test.parquet').write_bytes(response.content)
(OUT/'download_manifest.json').write_text(json.dumps({'traces':manifest,'public_test':{'url':url,'sha256':hashlib.sha256(response.content).hexdigest(),'bytes':len(response.content)}},indent=2))
print('Verified all pinned trace blobs and downloaded untouched public text test')
