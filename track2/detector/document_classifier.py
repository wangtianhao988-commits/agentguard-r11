"""Public Apache-2 L1 classifier only; no commercial L2 assets or remote code."""
import hashlib, json, time
from collections import OrderedDict
from pathlib import Path

class DocumentClassifier:
    def __init__(self, directory):
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer
        directory=Path(directory)
        manifest=json.loads((directory/'provenance.json').read_text())
        for entry in manifest['files']:
            assert hashlib.sha256((directory/entry['path']).read_bytes()).hexdigest()==entry['sha256']
        self.np=np
        options=ort.SessionOptions();options.intra_op_num_threads=options.inter_op_num_threads=1
        self.session=ort.InferenceSession(str(directory/'onnx/int8_int4_embeddings/model.onnx'),sess_options=options,providers=['CPUExecutionProvider'])
        self.tokenizer=Tokenizer.from_file(str(directory/'tokenizer.json'))
        self.tokenizer.no_padding();self.tokenizer.no_truncation()
        self.model_sha256=next(v['sha256'] for v in manifest['files'] if v['path'].endswith('.onnx'))
        self.threshold=.5;self.cache=OrderedDict();self.stats={'inferences':0,'cache_hits':0,'cpu_ns':0,'wall_ns':0}
    def score(self,text):
        key=hashlib.sha256(text.encode()).hexdigest()
        if key in self.cache:
            self.stats['cache_hits']+=1;self.cache.move_to_end(key);return self.cache[key]
        start,wall=time.thread_time_ns(),time.perf_counter_ns()
        encoded=self.tokenizer.encode(text)
        # Development probe reports truncation. Deployment must define full
        # document window aggregation before any independently scored test.
        values={'input_ids':self.np.asarray([encoded.ids[:2048]],dtype=self.np.int64),'attention_mask':self.np.asarray([encoded.attention_mask[:2048]],dtype=self.np.int64)}
        logits=self.session.run(None,{v.name:values[v.name] for v in self.session.get_inputs()})[0][0].astype(self.np.float64)
        probabilities=self.np.exp(logits-logits.max());score=float(probabilities[1]/probabilities.sum())
        self.stats['inferences']+=1;self.stats['cpu_ns']+=time.thread_time_ns()-start;self.stats['wall_ns']+=time.perf_counter_ns()-wall
        result={'score':score,'block':score>=self.threshold,'inspection_incomplete':len(encoded.ids)>2048}
        self.cache[key]=result
        if len(self.cache)>2048:self.cache.popitem(last=False)
        return result
