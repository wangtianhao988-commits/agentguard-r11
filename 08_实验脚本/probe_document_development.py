"""Probe unique already-used attack payloads and normal results; not generalization."""
import json,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'track2/detector'))
from document_classifier import DocumentClassifier
from evaluate_tiny_development import content
if __name__=='__main__':
    development=ROOT/'07_修复验证/development_R10'
    attack=set();benign=set()
    for entry in json.loads((development/'selection.json').read_text()):
        trace=json.loads((development/'raw'/entry['path']).read_text(encoding='utf-8'))
        if trace['attack_type'] not in (None,'none'):
            attack.update(v for v in trace.get('injections',{}).values() if isinstance(v,str))
        else:
            benign.update(content(m.get('content')) for m in trace['messages'] if m['role']=='tool')
    model=DocumentClassifier(ROOT/'track2/models/r11_wolf');rows=[];start=time.perf_counter()
    for label,texts in [(True,attack),(False,benign)]:
        for text in sorted(texts):
            rows.append({'attack':label,'text_sha256':__import__('hashlib').sha256(text.encode()).hexdigest(),**model.score(text)})
            if len(rows)%100==0:print('development probe',len(rows),flush=True)
    output=ROOT/'07_修复验证/wolf_development';output.mkdir(exist_ok=True)
    summary={'development_only':True,'wall_s':time.perf_counter()-start,'stats':model.stats,
             'attack_payloads':{'n':len(attack),'detected':sum(v['attack'] and v['block'] for v in rows)},
             'normal_tool_results':{'n':len(benign),'false_positive':sum(not v['attack'] and v['block'] for v in rows)},
             'truncated':sum(v['inspection_incomplete'] for v in rows)}
    (output/'cases.jsonl').write_text(''.join(json.dumps(v)+'\n' for v in rows));(output/'summary.json').write_text(json.dumps(summary,indent=2))
    print(json.dumps(summary),flush=True)
