"""Cheap learned text scorer, JSON parameters only, bounded feature extraction.

It supplies a candidate signal, never a permission. Sparse word/subword weights
are learned from development annotations; no hand-maintained attack-name table.
"""
import hashlib,json,math,re,time
from collections import OrderedDict
from pathlib import Path
TOKEN=re.compile(r'[\u4e00-\u9fff]|[a-zA-Z\u00c0-\u024f0-9]+')

def features(text):
    words=TOKEN.findall(text[:8192].casefold())[:1024]
    output={'w:'+word for word in words}
    output.update('b:'+left+' '+right for left,right in zip(words,words[1:]))
    output.update('c:'+word[start:start+3] for word in words if 3<=len(word)<=32 for start in range(len(word)-2))
    return output

class SparseInjectionModel:
    def __init__(self,directory):
        self.head=json.loads((Path(directory)/'head.json').read_text(encoding='utf-8'))
        parameters={key:self.head[key] for key in ['weights','intercept','threshold']}
        assert isinstance(self.head['weights'],dict) and len(self.head['weights'])<=50000
        assert all(isinstance(k,str) and len(k)<=128 and isinstance(v,(int,float)) and not isinstance(v,bool) and math.isfinite(v) for k,v in self.head['weights'].items())
        assert math.isfinite(self.head['intercept']) and 0<=self.head['threshold']<=1
        self.model_sha256=hashlib.sha256(json.dumps(parameters,sort_keys=True).encode()).hexdigest()
        assert self.model_sha256==self.head['head_parameters_sha256']
        self.cache=OrderedDict();self.stats={'inferences':0,'cache_hits':0,'cpu_ns':0,'wall_ns':0}
    def score(self,text):
        key=hashlib.sha256(text.encode()).hexdigest()
        if key in self.cache:
            self.stats['cache_hits']+=1;self.cache.move_to_end(key);return self.cache[key]
        started,wall=time.thread_time_ns(),time.perf_counter_ns()
        z=self.head['intercept']+sum(self.head['weights'].get(feature,0) for feature in features(text))
        value=1/(1+math.exp(-max(-60,min(60,z))))
        self.stats['inferences']+=1;self.stats['cpu_ns']+=time.thread_time_ns()-started;self.stats['wall_ns']+=time.perf_counter_ns()-wall
        self.cache[key]=value
        if len(self.cache)>2048:self.cache.popitem(last=False)
        return value
    def inspect(self,texts):
        best=None;windows=0;incomplete=False
        for text in texts:
            chunks=[text[start:start+1600] for start in range(0,len(text),1200)]
            for chunk in chunks:
                if windows>=16:incomplete=True;break
                windows+=1;score=self.score(chunk)
                if best is None or score>best['score']:
                    best={'score':score,'threshold':self.head['threshold'],'window_sha256':hashlib.sha256(chunk.encode()).hexdigest(),'encoder_sha256':self.model_sha256,'head_sha256':self.model_sha256}
        if best:best.update(block=best['score']>=self.head['threshold'],windows=windows,inspection_incomplete=incomplete)
        return best
