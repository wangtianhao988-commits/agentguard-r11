"""Pinned, data-only distilled classifier with explicit coverage accounting.

Probabilities classify untrusted text, never authorize an action. The reference
head/tail preprocessing and published threshold are preserved. Additional token
windows cover the middle rather than silently discarding it. A bounded budget
reports incomplete inspection; callers must not equate this with a safe result.
"""
import hashlib
import json
import time
from collections import OrderedDict
from pathlib import Path


class InjectionClassifier:
    def __init__(self, directory):
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer
        directory = Path(directory)
        manifest = json.loads((directory / 'provenance.json').read_text(encoding='utf-8'))
        for item in manifest['files']:
            assert hashlib.sha256((directory / item['path']).read_bytes()).hexdigest() == item['sha256'], item['path']
        self.np = np
        options = ort.SessionOptions()
        options.intra_op_num_threads = options.inter_op_num_threads = 1
        self.session = ort.InferenceSession(str(directory / 'onnx/opset11/model.int8.onnx'), sess_options=options, providers=['CPUExecutionProvider'])
        self.tokenizer = Tokenizer.from_file(str(directory / 'tokenizer.json'))
        self.tokenizer.no_padding()
        self.tokenizer.no_truncation()
        self.cls, self.sep, self.pad = [self.tokenizer.token_to_id(s) for s in ('[CLS]', '[SEP]', '[PAD]')]
        assert None not in (self.cls, self.sep, self.pad)
        thresholds = json.loads((directory / 'deployment/fastly/calibrated_thresholds.json').read_text())
        self.threshold = thresholds['injection']['T_block_at_1pct_FPR']
        self.model_sha256 = next(v['sha256'] for v in manifest['files'] if v['path'].endswith('.onnx'))
        self.policy_sha256 = hashlib.sha256(json.dumps({'threshold': self.threshold, 'sequence': 128, 'overlap': 32, 'window_budget': 16}, sort_keys=True).encode()).hexdigest()
        self.cache = OrderedDict()
        self.stats = {'inferences': 0, 'cache_hits': 0, 'cpu_ns': 0, 'wall_ns': 0}

    def score_tokens(self, tokens):
        key = tuple(tokens)
        if key in self.cache:
            self.cache.move_to_end(key)
            self.stats['cache_hits'] += 1
            return self.cache[key]
        started, wall = time.thread_time_ns(), time.perf_counter_ns()
        ids = [self.cls] + list(tokens) + [self.sep]
        mask = [1] * len(ids)
        ids += [self.pad] * (128 - len(ids))
        mask += [0] * (128 - len(mask))
        values = {'input_ids': self.np.asarray([ids], dtype=self.np.int64), 'attention_mask': self.np.asarray([mask], dtype=self.np.int64)}
        logits = self.session.run(None, values)[0][0].astype(self.np.float64)
        probs = self.np.exp(logits - logits.max())
        score = float(probs[1] / probs.sum())
        self.stats['inferences'] += 1
        self.stats['cpu_ns'] += time.thread_time_ns() - started
        self.stats['wall_ns'] += time.perf_counter_ns() - wall
        self.cache[key] = score
        if len(self.cache) > 2048:
            self.cache.popitem(last=False)
        return score

    def inspect(self, texts, middle_windows=True):
        best = None
        windows = 0
        incomplete = False
        for text in texts:
            bounded = text[:65536]
            incomplete |= len(text) > len(bounded)
            raw = self.tokenizer.encode(bounded, add_special_tokens=False).ids
            candidates = [raw if len(raw) <= 126 else raw[:63] + raw[-63:]]
            if middle_windows and len(raw) > 126:
                candidates += [raw[start:start + 126] for start in range(0, len(raw), 94)]
            seen = set()
            for tokens in candidates:
                key = tuple(tokens)
                if key in seen:
                    continue
                seen.add(key)
                if windows >= 16:
                    incomplete = True
                    break
                windows += 1
                score = self.score_tokens(tokens)
                if best is None or score > best['score']:
                    best = {'score': score, 'threshold': self.threshold, 'window_sha256': hashlib.sha256(json.dumps(tokens).encode()).hexdigest(), 'encoder_sha256': self.model_sha256, 'head_sha256': self.policy_sha256}
        if best:
            best.update(block=best['score'] >= self.threshold, windows=windows, inspection_incomplete=incomplete)
        return best
