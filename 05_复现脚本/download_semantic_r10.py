"""Pinned public assets only; no remote Python code or pickled model loading."""
import hashlib,json,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'07_修复验证/semantic_training';MODEL=ROOT/'track2/models/r10'
MODEL.mkdir(parents=True,exist_ok=True)
data=json.loads((OUT/'datasets_metadata.json').read_text());model=json.loads((OUT/'models_metadata.json').read_text())
rows=[('dataset','deepset/prompt-injections',data['sha'],next(r['rfilename'] for r in data['siblings'] if '/train-' in r['rfilename']),OUT/'train.parquet')]
for name in ['onnx/model_quint8_avx2.onnx','tokenizer.json','config.json','README.md']:
    rows.append(('model','sentence-transformers/paraphrase-MiniLM-L3-v2',model['sha'],name,MODEL/Path(name).name))
manifest=[]
for kind,repo,commit,name,dest in rows:
    url=f'https://huggingface.co/{"datasets/" if kind=="dataset" else ""}{repo}/resolve/{commit}/{name}'
    blob=urllib.request.urlopen(url,timeout=120).read();dest.write_bytes(blob)
    manifest.append({'kind':kind,'repository':repo,'commit':commit,'source_path':name,'path':dest.relative_to(ROOT).as_posix(),'bytes':len(blob),'sha256':hashlib.sha256(blob).hexdigest()})
    print(kind,name,len(blob),flush=True)
(OUT/'download_manifest.json').write_text(json.dumps(manifest,indent=2))
