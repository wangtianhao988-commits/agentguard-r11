"""CPU-light candidate trained ONLY on used R10/public-train development data."""
import hashlib,json,sys,time
from pathlib import Path
import numpy as np,pyarrow.parquet as pq
from scipy.sparse import csr_matrix
from sklearn.linear_model import LogisticRegression
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'track2/detector'))
from sparse_injection_model import features
from evaluate_tiny_development import content
records={}
def add(text,label,group):
    if not isinstance(text,str) or not text.strip():return
    key=hashlib.sha256(text.strip().encode()).hexdigest()
    if key in records:
        if records[key]['label']!=label:records[key]['conflict']=True
        records[key]['groups'].add(group)
    else:records[key]={'text':text,'label':int(label),'groups':{group}}
for row in pq.read_table(ROOT/'07_修复验证/semantic_training/train.parquet').to_pylist():add(row['text'],row['label'],'public:'+hashlib.sha256(row['text'].encode()).hexdigest())
development=ROOT/'07_修复验证/development_R10'
for entry in json.loads((development/'selection.json').read_text()):
    trace=json.loads((development/'raw'/entry['path']).read_text(encoding='utf-8'));group='/'.join(Path(entry['path']).parts[2:4])
    if trace['attack_type'] not in (None,'none'):
        for text in trace.get('injections',{}).values():add(text,1,group)
    else:
        for message in trace['messages']:
            if message['role']=='tool':add(content(message.get('content')),0,group)
train=[];calibration=[];excluded=[]
for key,row in sorted(records.items()):
    folds={int(hashlib.sha256(group.encode()).hexdigest()[:8],16)%5 for group in row['groups']}
    if row.get('conflict') or (0 in folds and len(folds)>1):excluded.append(key);continue
    (calibration if folds=={0} else train).append((key,row))
vocabulary={feature:index for index,feature in enumerate(sorted({feature for key,row in train for feature in features(row['text'])}))}
def matrix(rows):
    positions=[];columns=[]
    for index,(key,row) in enumerate(rows):
        values=[vocabulary[f] for f in features(row['text']) if f in vocabulary];positions.extend([index]*len(values));columns.extend(values)
    return csr_matrix((np.ones(len(columns)),(positions,columns)),shape=(len(rows),len(vocabulary)))
x=matrix(train);z=matrix(calibration);y=np.array([r['label'] for key,r in train]);truth=np.array([r['label'] for key,r in calibration]);candidates=[]
for c in [.1,1,10]:
    model=LogisticRegression(C=c,class_weight='balanced',max_iter=1000,random_state=11).fit(x,y)
    scores=model.predict_proba(z)[:,1]
    choices=[.5,*sorted({min(1,float(s)+1e-6) for s in scores[truth==0] if s>=.5}),1]
    threshold=min(t for t in choices if np.mean(scores[truth==0]>=t)<=.02)
    candidates.append((int(((scores>=threshold)&(truth==1)).sum()),-c,model,threshold,int(((scores>=threshold)&(truth==0)).sum())))
tp,negative_c,model,threshold,fp=max(candidates,key=lambda v:v[:2])
parameters={'weights':{feature:float(model.coef_[0][index]) for feature,index in vocabulary.items()},'intercept':float(model.intercept_[0]),'threshold':threshold}
head={**parameters,'version':1,'head_parameters_sha256':hashlib.sha256(json.dumps(parameters,sort_keys=True).encode()).hexdigest()}
output=ROOT/'track2/models/r11_sparse';output.mkdir(exist_ok=True);(output/'head.json').write_text(json.dumps(head,ensure_ascii=False),encoding='utf-8')
evidence=ROOT/'07_修复验证/sparse_development';evidence.mkdir(exist_ok=True)
summary={'development_only':True,'train_n':len(train),'calibration_n':len(calibration),'excluded_cross_fold_shared_or_conflicting':len(excluded),'calibration_positive':int(truth.sum()),'calibration_negative':int((truth==0).sum()),'calibration_tp':tp,'calibration_fp':fp,'threshold':threshold,'C':-negative_c,'features':len(vocabulary),'split':'suite/user_task groups, shared cross-fold texts excluded; public rows by content hash','BIPIA_used_for_training':False,'hashes':{'train':[k for k,r in train],'calibration':[k for k,r in calibration],'excluded':excluded}}
(evidence/'training.json').write_text(json.dumps(summary,indent=2));print(json.dumps({k:v for k,v in summary.items() if k!='hashes'}),flush=True)
