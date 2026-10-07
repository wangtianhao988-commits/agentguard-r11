"""Freeze public-train split; calibrate only development data; never download test."""
import argparse,hashlib,json,sys,time
from pathlib import Path
import numpy as np
import pyarrow.parquet as pq
from sklearn.linear_model import LogisticRegression
ROOT=Path(__file__).resolve().parents[1];DATA=ROOT/'07_修复验证/semantic_training';MODEL=ROOT/'track2/models/r10'
parser=argparse.ArgumentParser();parser.add_argument('--output-dir',type=Path,required=True);args=parser.parse_args()
OUT=args.output_dir.resolve();OUT.mkdir(parents=True,exist_ok=False)
sys.path.insert(0,str(ROOT/'track2/detector'))
from semantic_model import SemanticModel
rows=pq.read_table(DATA/'train.parquet').to_pylist();unique={}
for row in rows:
    key=hashlib.sha256(row['text'].strip().encode()).hexdigest()
    if key in unique:assert unique[key]['label']==row['label']
    unique[key]=row
train=[(k,r) for k,r in unique.items() if int(k[:8],16)%5!=0]
calibration=[(k,r) for k,r in unique.items() if int(k[:8],16)%5==0]
(OUT/'split.json').write_text(json.dumps({'training_hashes':[k for k,r in train],'calibration_hashes':[k for k,r in calibration],
    'encoder':'frozen public MiniLM-L3 quantized; no fine-tuning','classifier':'L2 logistic regression C=10 balanced, random_state=10',
    'threshold_rule':'smallest threshold >=0.5 with <=2% calibration false positives; not an independent accuracy guarantee'},indent=2))
# Development-only AgentDojo texts; new Llama holdout remains unopened.
old=DATA/'development/runs'
extra={}
for file in sorted(old.rglob('*.json')):
    trace=json.loads(file.read_text(encoding='utf-8'))
    parts=file.relative_to(old).parts;group='/'.join(parts[1:3]);fold=int(hashlib.sha256(group.encode()).hexdigest()[:8],16)%5
    texts=[(m.get('content'),0) for m in trace['messages'] if m['role']=='tool'] if trace.get('attack_type') is None else [(v,1) for v in trace.get('injections',{}).values()]
    for text,label in texts:
        if not isinstance(text,str):continue
        # Positive annotation applies to the whole injected text, not every
        # arbitrary chunk which may contain only legitimate document data.
        chunks=[text] if label else [text[start:start+400] for start in range(0,len(text),300)]
        for chunk in chunks:
            if len(chunk.strip())<40:continue
            key=hashlib.sha256(chunk.strip().encode()).hexdigest()
            if key in unique:continue
            row=extra.setdefault(key,{'text':chunk,'label':label,'folds':set(),'groups':set()})
            row['folds'].add(fold);row['groups'].add(group)
            if row['label']!=label:row['conflict']=True
# Shared chunks across training/calibration task groups are excluded, rather than
# leaking identical documents into the calibration set.
extra={k:r for k,r in extra.items() if not r.get('conflict') and not (0 in r['folds'] and len(r['folds'])>1)}
train += [(k,r) for k,r in extra.items() if 0 not in r['folds']]
calibration += [(k,r) for k,r in extra.items() if r['folds']=={0}]
(OUT/'split_augmented.json').write_text(json.dumps({'training_hashes':[k for k,r in train],'calibration_hashes':[k for k,r in calibration], 'development_data':'old important_instructions whole injection text; old benign actual return windows', 'group_rule':'suite/user_task independent of model; cross-fold shared texts excluded','training_groups':sorted({g for k,r in train for g in r.get('groups',[]) }),'calibration_groups':sorted({g for k,r in calibration for g in r.get('groups',[]) }), 'new_test_data_not_read':True},indent=2))
model=SemanticModel(MODEL,require_head=False);started=time.perf_counter()
vectors=np.stack([model.embed(r['text']) for k,r in train+calibration]);labels=np.asarray([r['label'] for k,r in train+calibration]);n=len(train)
classifier=LogisticRegression(C=10,class_weight='balanced',random_state=10,max_iter=1000).fit(vectors[:n],labels[:n])
scores=classifier.predict_proba(vectors[n:])[:,1];y=labels[n:]
choices=[x for x in [0.5,*sorted(set(min(1.0,float(x)+0.0001) for x in scores if x>=0.5)),1.0] if float(np.mean(scores[y==0]>=x))<=.02]
threshold=min(choices) if choices else 1.0
parameters={'weights':classifier.coef_[0].tolist(),'intercept':float(classifier.intercept_[0]),'threshold':threshold}
head={**parameters,'version':1,'encoder_sha256':model.model_sha256,
      'head_parameters_sha256':hashlib.sha256(json.dumps(parameters,sort_keys=True).encode()).hexdigest()}
(OUT/'head.json').write_text(json.dumps(head,indent=2))
result={'train':n,'calibration':len(calibration),'threshold':threshold,'calibration_fp':int(((scores>=threshold)&(y==0)).sum()),
        'calibration_positive':int((y==1).sum()),'calibration_tp':int(((scores>=threshold)&(y==1)).sum()),
        'wall_s':time.perf_counter()-started,'model_stats':model.stats,'test_used_for_training':False,
        'test_download_present':(ROOT/'07_修复验证/external_r10/public_test.parquet').exists()}
(OUT/'training_result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))
