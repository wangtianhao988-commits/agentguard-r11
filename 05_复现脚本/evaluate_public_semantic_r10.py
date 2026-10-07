"""Untouched public test: text discrimination, never an agent blocking metric."""
import hashlib,json,sys
from pathlib import Path
import pyarrow.parquet as pq
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'07_修复验证/external_r10'
sys.path.insert(0,str(ROOT/'track2/detector'))
from semantic_model import SemanticModel
model=SemanticModel(ROOT/'track2/models/r10')
train=json.loads((ROOT/'07_修复验证/semantic_training/split_augmented.json').read_text())
seen=set(train['training_hashes'])|set(train['calibration_hashes']);rows=[]
for row in pq.read_table(OUT/'public_test.parquet').to_pylist():
    digest=hashlib.sha256(row['text'].strip().encode()).hexdigest();result=model.inspect([row['text']])
    rows.append({'sha256':digest,'label':row['label'],'overlaps_development':digest in seen,'score':result,'predicted':bool(result and result['block'])})
def score(data):
    positive=[r for r in data if r['label']==1];negative=[r for r in data if r['label']==0]
    tp=sum(r['predicted'] for r in positive);fp=sum(r['predicted'] for r in negative)
    return {'n':len(data),'positive':len(positive),'negative':len(negative),'tp':tp,'fn':len(positive)-tp,'fp':fp,'tn':len(negative)-fp,
        'recall':tp/len(positive) if positive else None,'fpr':fp/len(negative) if negative else None,
        'incomplete_windows':sum(bool(r['score'] and r['score']['inspection_incomplete']) for r in data)}
summary={'all_public_test':score(rows),'deduplicated_from_development':score([r for r in rows if not r['overlaps_development']]),
    'threshold':model.head['threshold'],'model_sha256':model.model_sha256,'head_sha256':model.head['head_parameters_sha256'],
    'model_stats':model.stats,'metric':'Injection text classification; not closed-loop agent attack detection or blocking'}
(OUT/'public_test_cases.json').write_text(json.dumps(rows,indent=2));(OUT/'public_test_summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary))
