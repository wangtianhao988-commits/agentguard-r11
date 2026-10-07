"""Frozen MiniLM embeddings + learned binary head, CPU-only bounded inference.

This classifies injection-like language; it never grants a tool permission. No
remote code or pickle, one ONNX CPU thread, exact-text cache, bounded windows.
"""
import hashlib,json,math,re,time
from collections import OrderedDict
from pathlib import Path


class SemanticModel:
    def __init__(self, directory, require_head=True, encoder_file='model_quint8_avx2.onnx'):
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer
        self.np=np;directory=Path(directory)
        options=ort.SessionOptions();options.intra_op_num_threads=1;options.inter_op_num_threads=1
        self.session=ort.InferenceSession(str(directory/encoder_file),sess_options=options,providers=['CPUExecutionProvider'])
        self.tokenizer=Tokenizer.from_file(str(directory/'tokenizer.json'))
        # Single-text inference needs no padding. Actual length stays <=128;
        # this removes quadratic work on masked padding positions. Quantized
        # activations change slightly, so retrain/calibrate the frozen head on
        # development data before evaluating the untouched external holdout.
        self.tokenizer.enable_truncation(max_length=128);self.tokenizer.no_padding()
        self.head=json.loads((directory/'head.json').read_text()) if require_head else None
        self.cache=OrderedDict();self.stats={'inferences':0,'cache_hits':0,'cpu_ns':0,'wall_ns':0}
        self.model_sha256=hashlib.sha256((directory/encoder_file).read_bytes()).hexdigest()
        if self.head:
            assert self.head['encoder_sha256']==self.model_sha256,'semantic model/head mismatch'
            self.weights=np.asarray(self.head['weights'],dtype=np.float64)
            parameters={k:self.head[k] for k in ['weights','intercept','threshold']}
            assert hashlib.sha256(json.dumps(parameters,sort_keys=True).encode()).hexdigest()==self.head['head_parameters_sha256'],'semantic head checksum mismatch'
            assert len(self.weights)==384 and np.isfinite(self.weights).all() and math.isfinite(self.head['intercept']) and 0<=self.head['threshold']<=1,'invalid semantic head'

    def embed(self,text):
        np=self.np;started=time.thread_time_ns();wall=time.perf_counter_ns()
        encoded=self.tokenizer.encode(text[:12000])
        values={'input_ids':np.asarray([encoded.ids],dtype=np.int64),
                'attention_mask':np.asarray([encoded.attention_mask],dtype=np.int64),
                'token_type_ids':np.asarray([encoded.type_ids],dtype=np.int64)}
        outputs=self.session.run(None,{v.name:values[v.name] for v in self.session.get_inputs()})
        embedding=outputs[0]
        if embedding.ndim==3:
            mask=values['attention_mask'][...,None];embedding=(embedding*mask).sum(1)/np.maximum(mask.sum(1),1)
        vec=embedding[0];vec=vec/np.maximum(np.linalg.norm(vec),1e-12)
        self.stats['inferences']+=1;self.stats['cpu_ns']+=time.thread_time_ns()-started;self.stats['wall_ns']+=time.perf_counter_ns()-wall
        return vec

    def score(self,text):
        key=hashlib.sha256(text.encode()).hexdigest()
        if key in self.cache:
            self.stats['cache_hits']+=1;self.cache.move_to_end(key);return self.cache[key]
        z=float(self.embed(text)@self.weights)+self.head['intercept']
        score=1/(1+math.exp(-max(-60,min(60,z))))
        self.cache[key]=score
        if len(self.cache)>2048:self.cache.popitem(last=False)
        return score

    def inspect(self,texts):
        best=None;windows=0;incomplete=False
        for text in texts:
            # Short machine values lack sentence context; legacy rules still judge them.
            if len(re.findall(r'[A-Za-z]{2,}|[\u4e00-\u9fff]',text))<8:continue
            chunks=[text[start:start+400] for start in range(0,len(text),300)]
            if len(chunks)>8:incomplete=True
            for chunk in chunks[:8]:
                if windows>=8:incomplete=True;break
                windows+=1;score=self.score(chunk)
                if best is None or score>best['score']:
                    best={'score':score,'threshold':self.head['threshold'],
                          'window_sha256':hashlib.sha256(chunk.encode()).hexdigest(),
                          'encoder_sha256':self.model_sha256,'head_sha256':self.head['head_parameters_sha256']}
        if best:best.update(block=best['score']>=best['threshold'],windows=windows,inspection_incomplete=incomplete)
        return best
