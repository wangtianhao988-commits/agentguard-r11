"""Pinned inert trace JSON with Git object checks; no public test re-download."""
import concurrent.futures,hashlib,json,threading,time
from pathlib import Path
import requests
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'07_修复验证/external_r11_gemini'
protocol=json.loads((OUT/'protocol.json').read_text());selection=json.loads((OUT/'selection.json').read_text());local=threading.local()
def fetch(row):
    if not hasattr(local,'client'):local.client=requests.Session()
    target=OUT/'raw'/row['path'];target.parent.mkdir(parents=True,exist_ok=True)
    if not target.exists():
        url='https://raw.githubusercontent.com/ethz-spylab/agentdojo/'+protocol['commit']+'/'+row['path']
        for attempt in range(5):
            try:
                response=local.client.get(url,timeout=30);response.raise_for_status();data=response.content
                if hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()!=row['sha']:raise ValueError('Git blob mismatch')
                json.loads(data);target.write_bytes(data);break
            except Exception:
                if attempt==4:raise
                time.sleep(attempt+1)
    data=target.read_bytes()
    assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==row['sha']
    return {'path':row['path'],'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'git_blob':row['sha']}
rows=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
    for job in concurrent.futures.as_completed([pool.submit(fetch,row) for row in selection]):
        rows.append(job.result())
        if len(rows)%200==0:print('Verified',len(rows),flush=True)
(OUT/'download_manifest.json').write_text(json.dumps({'traces':sorted(rows,key=lambda r:r['path'])},indent=2))
print('All pinned JSON blobs verified')
