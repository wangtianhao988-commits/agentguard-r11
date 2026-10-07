"""Paired encoder timing on identical development text; head-free, not detection."""
import json,sys,time
from pathlib import Path
import numpy as np
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'track2/detector'))
from semantic_model import SemanticModel
old=SemanticModel(ROOT/'track2/models/r10',False)
new=SemanticModel(ROOT/'track2/models/r11_semantic',False,'onnx/model_qint8_avx512_vnni.onnx')
texts=['<html><body>Advisory for CVE-2026-'+str(1000+i)+': no known issues.</body></html>' for i in range(300)]
for model in [old,new]:
    for text in texts[:10]:model.embed(text)
vectors={};results=[]
for name,model in [('old',old),('new',new),('new_repeat',new),('old_repeat',old)]:
    started=time.thread_time_ns();vectors[name]=np.stack([model.embed(t) for t in texts])
    results.append({'name':name,'thread_cpu_ms':(time.thread_time_ns()-started)/1e6})
out=ROOT/'07_修复验证/encoder_development';out.mkdir(exist_ok=True)
summary={'development_only':True,'samples':len(texts),'measurements':results,'mean_embedding_cosine':float(np.sum(vectors['old']*vectors['new'],axis=1).mean())}
(out/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True)
