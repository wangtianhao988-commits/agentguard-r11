"""Native R10 facade: shared immutable semantic model and private business ledger."""
import json,os
from pathlib import Path
from generalization import views
from business_flow import BusinessFlow

_MODEL=None
_MODEL_KEY=None


class R10Security:
    def __init__(self):
        global _MODEL,_MODEL_KEY
        self.features=set(os.environ.get('GUARD_R10_COMPONENTS','semantic,flow').split(','))
        self.semantic=None;self.flow=None
        self.intent=None;self.backend=None
        if os.environ.get('GUARD_R11_INTENT_URL'):
            from contextual_intent import ContextualIntent
            self.intent=ContextualIntent(os.environ['GUARD_R11_INTENT_URL'],os.environ.get('GUARD_R11_MODEL_REVISION','bc640142c66e1fdd12af0bd68f40445458f3869b'),float(os.environ.get('GUARD_R11_VERIFIER_TIMEOUT','.75')))
        if 'semantic' in self.features:
            from semantic_model import SemanticModel
            directory=Path(os.environ.get('GUARD_R10_MODEL_PATH',str(Path(__file__).resolve().parents[1]/'models/r10')))
            backend='minilm'
            if os.environ.get('GUARD_R11_SPARSE')=='1':
                from sparse_injection_model import SparseInjectionModel
                directory=Path(os.environ.get('GUARD_R11_SPARSE_PATH',str(Path(__file__).resolve().parents[1]/'models/r11_sparse')))
                backend='sparse'
            key=(backend,str(directory.resolve()))
            if _MODEL is None or _MODEL_KEY!=key:
                _MODEL=SparseInjectionModel(directory) if backend=='sparse' else SemanticModel(directory)
                _MODEL_KEY=key
            self.semantic=_MODEL
            self.backend=backend
        if 'flow' in self.features:
            policy_path=os.environ.get('GUARD_R10_DATA_POLICY_PATH')
            policy=json.loads(Path(policy_path).read_text()) if policy_path else None
            graph_path=os.environ.get('GUARD_GRAPH_STATE_PATH')
            self.flow=BusinessFlow(policy,str(Path(graph_path).with_suffix('.business.sqlite')) if graph_path else None)

    def inspect_result(self,body,s=None):
        if not self.semantic:return None
        from session import _unwrap_tool_result
        texts=views(_unwrap_tool_result(body));result=self.semantic.inspect(texts)
        if result and result['block'] and self.intent and self.backend=='sparse':
            # Sparse score triggers verification; it does not unilaterally deny
            # ordinary instructional business text. No model result grants rights.
            selected=None
            import hashlib
            for text in texts:
                for start in range(0,len(text),1200):
                    chunk=text[start:start+1600]
                    if hashlib.sha256(chunk.encode()).hexdigest()==result['window_sha256']:selected=chunk;break
                if selected is not None:break
            if selected is None:return {**result,'block':True,'contextual_verifier_error':'scored window unavailable'}
            try:
                verdict=self.intent.judge_return(s.prompt if s else '',selected if selected is not None else '')
                result={**result,'block':verdict['malicious'],'contextual_verdict':verdict}
            except Exception as error:
                result={**result,'block':True,'contextual_verifier_error':type(error).__name__}
        return result

    def findings(self,s,evaluate_intent=True):
        out=self.intent.check(s) if self.intent and evaluate_intent else []
        if not self.flow or not s.calls:return out
        from rules import Finding
        principal=(s.identity or {}).get('sub');index=len(s.calls)-1
        return out+[Finding(f['rule_id'],'BLOCK',.95,s.instance_id,f['summary'],{'call_index':index,**f},[f'{s.calls[index].server}.{s.calls[index].tool}']) for f in self.flow.check(principal,s.instance_id,s.calls[index])]

    def observe(self,s,call):
        if self.flow:self.flow.observe((s.identity or {}).get('sub'),s.instance_id,call,call.result,call.ok)

    def snapshot(self):
        return {'version':'R11' if self.backend=='sparse' or self.intent else 'R10','features':sorted(self.features),'semantic_backend':self.backend,
            'semantic':dict(self.semantic.stats,threshold=self.semantic.head['threshold'],encoder_sha256=self.semantic.model_sha256,head_sha256=self.semantic.head['head_parameters_sha256']) if self.semantic else None,
            'business_flow':dict(self.flow.stats,saturated=self.flow.saturated,persistence=self.flow.db is not None,restored=self.flow.restored,namespace=self.flow.namespace) if self.flow else None,
            'contextual_intent':dict(self.intent.stats,model_revision=self.intent.revision) if self.intent else None}

    def close(self):
        if self.flow:self.flow.close()
        if self.intent:self.intent.close()
