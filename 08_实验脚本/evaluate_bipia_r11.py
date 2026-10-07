"""Independent frozen text-return comparison. Never interpret attacker text as code."""
import argparse,hashlib,json,random,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'07_修复验证/external_candidate_bipia'
parser=argparse.ArgumentParser();parser.add_argument('--method',choices=['R10','Tiny','Wolf_L1'],required=True);parser.add_argument('--source-snapshot',action='store_true',help='Reproduce preserved pre-test implementation, not current R11');parser.add_argument('--output-name');args=parser.parse_args()
protocol=json.loads((OUT/'protocol.json').read_text())
source=OUT/'source_snapshot' if args.source_snapshot else ROOT
for relative,digest in protocol['runtime_sources'].items():
    assert hashlib.sha256((source/relative).read_bytes()).hexdigest()==digest,'Frozen source changed: '+relative
for relative,digest in protocol['model_assets'].items():
    assert hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()==digest,'Frozen model changed: '+relative
for item in json.loads((OUT/'download_manifest.json').read_text()):assert hashlib.sha256((OUT/'raw'/item['path']).read_bytes()).hexdigest()==item['sha256']
sys.path.insert(0,str(source/'track2/detector'))
if args.method=='R10':
    from semantic_model import SemanticModel
    from generalization import injection_evidence
    model=SemanticModel(ROOT/'track2/models/r10')
    def predict(text):
        rule=injection_evidence(text);semantic=model.inspect([text]);return {'block':bool(rule or (semantic and semantic['block'])),'rule':rule,'semantic':semantic,'inspection_incomplete':bool(semantic and semantic.get('inspection_incomplete'))}
elif args.method=='Tiny':
    from injection_classifier import InjectionClassifier
    model=InjectionClassifier(ROOT/'track2/models/r11_tiny')
    def predict(text):return model.inspect([text]) or {'block':False}
else:
    from document_classifier import DocumentClassifier
    model=DocumentClassifier(ROOT/'track2/models/r11_wolf')
    predict=model.score
from nltk.tokenize.punkt import PunktSentenceTokenizer
attacks=json.loads((OUT/'raw/benchmark/text_attack_test.json').read_text(encoding='utf-8'))
flat={f'{name}-{index}':text for name,texts in attacks.items() for index,text in enumerate(texts)}
samples=[]
for domain in ['email','table']:
    contexts=[json.loads(line) for line in (OUT/f'raw/benchmark/{domain}/test.jsonl').read_text(encoding='utf-8').splitlines()]
    for index,item in enumerate(contexts):samples.append({'id':f'{domain}/normal/{index}','attack':False,'domain':domain,'context_id':index,'text':item['context']})
    for attack_id,payload in sorted(flat.items()):
        index=int(hashlib.sha256(attack_id.encode()).hexdigest()[:8],16)%len(contexts);context=contexts[index]['context']
        sentence_indexes=list(PunktSentenceTokenizer().span_tokenize(context));start,_=random.Random(protocol['seed']).sample(sentence_indexes,k=1)[0]
        for position,text in [('start',payload+'\n'+context),('end',context+'\n'+payload),('middle',context[:start]+'\n'+payload+'\n'+context[start:])]:
            samples.append({'id':f'{domain}/{attack_id}/{position}','attack':True,'domain':domain,'context_id':index,'attack_id':attack_id,'position':position,'text':text})
name=args.output_name or args.method
if Path(name).name!=name:raise ValueError('Output name must be one directory name')
destination=OUT/'results'/name;destination.mkdir(parents=True,exist_ok=False)
rows=[];began=time.perf_counter()
for item in samples:
    result=predict(item['text']);rows.append({**{k:v for k,v in item.items() if k!='text'},'text_sha256':hashlib.sha256(item['text'].encode()).hexdigest(),**result})
    if len(rows)%200==0:print(args.method,len(rows),flush=True)
def aggregate(selected):return {'n':len(selected),'detected':sum(v['block'] for v in selected),'incomplete':sum(v.get('inspection_incomplete',False) for v in selected)}
summary={'independent_project_test':True,'public_model_training_overlap_unknown':True,'method':args.method,'metric':protocol['metric'],'wall_s':time.perf_counter()-began,'unique_payloads':len(flat),'attack':aggregate([r for r in rows if r['attack']]),'normal':aggregate([r for r in rows if not r['attack']]),'stats':model.stats,
 'by_position':{p:aggregate([r for r in rows if r.get('position')==p]) for p in ['start','middle','end']}}
if args.source_snapshot:summary.update(independent_project_test=False,frozen_reproduction_only=True,source_snapshot=str(source.relative_to(ROOT)))
(destination/'cases.jsonl').write_text(''.join(json.dumps(v,ensure_ascii=False)+'\n' for v in rows),encoding='utf-8');(destination/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True)
