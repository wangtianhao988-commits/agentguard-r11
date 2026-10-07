"""Enforce a bound plan against actual LLM-proposed tool calls.

Unlike a fixed executor, this checks the model's real choices. Trust is established
before external data is read. Text, aliases, model reasoning and result metadata
cannot add steps or alter control arguments. Caller must log each denial and stop.
"""
import copy
from trusted_plan import PlanDenied, bounded_json, digest
from controlled_executor import DataValue

class ExecutionContract:
    def __init__(self, plans, principal, plan_id, inputs):
        self.bound=plans.bind(principal,plan_id,inputs)
        self.index=0;self.results={};self.pending=None;self.audit=[]

    @property
    def completed(self):return self.index==len(self.bound['plan']['steps']) and self.pending is None

    def expected(self):
        if self.completed:raise PlanDenied('approved task already completed')
        step=self.bound['plan']['steps'][self.index];arguments={};sources=[]
        for key,reference in step['arguments'].items():
            kind=next(iter(reference));origin=reference[kind]
            if kind=='literal':value=origin
            elif kind=='user':value=self.bound['inputs'][origin]
            else:
                record=self.results.get(origin[0])
                if record is None:raise PlanDenied('required actual result absent')
                if not record.labels<=set(step.get('accept_labels',[])):raise PlanDenied('unreleased data labels')
                value=record.value
                try:
                    for segment in origin[1:]:value=value[segment]
                except (KeyError,IndexError,TypeError):raise PlanDenied('required actual result field absent')
                sources.append({'parameter':key,'source':record.source,'labels':sorted(record.labels)})
            arguments[key]=copy.deepcopy(value)
        return step,arguments,sources

    def authorize(self, server, tool, arguments, call_id):
        if self.pending is not None:raise PlanDenied('prior actual call has not returned')
        bounded_json(arguments)
        if not isinstance(call_id,str) or not call_id:raise PlanDenied('actual call ID required')
        step,expected,sources=self.expected()
        # Canonical JSON retains bool/int type distinctions and nested structure.
        if server!=step['server'] or tool!=step['tool'] or digest(arguments)!=digest(expected):
            raise PlanDenied('model call differs from pre-external authorization')
        self.pending=(call_id,step)
        self.audit.append({'event':'authorized','call_id':call_id,'step':step['id'],'server':server,'tool':tool,'arguments_sha256':digest(arguments),'sources':sources,'binding_sha256':self.bound['binding_sha256']})
        return copy.deepcopy(arguments)

    def observe(self, call_id, result):
        if self.pending is None or self.pending[0]!=call_id:raise PlanDenied('unmatched actual call result')
        bounded_json(result)
        if isinstance(result,dict) and 'error' in result:raise PlanDenied('actual tool failed')
        step=self.pending[1]
        labels=frozenset(step.get('result_labels',['untrusted']))
        self.results[step['id']]=DataValue(copy.deepcopy(result),step['id'],labels)
        self.audit.append({'event':'observed','call_id':call_id,'result_sha256':digest(result),'labels':sorted(labels)})
        self.pending=None;self.index+=1

    def finish_remaining(self, transport):
        """Recover only already-approved steps after a rejected model proposal.

        Never retry an in-flight effect: its outcome may be ambiguous. Remaining
        steps use the same literal/user/data origins and label checks. Recovery is
        logged as deterministic execution, not fabricated model behavior.
        """
        if self.pending is not None:raise PlanDenied('cannot replay an in-flight effect')
        while not self.completed:
            step,arguments,_=self.expected()
            call_id=f'contract-recovery-{self.index}'
            self.authorize(step['server'],step['tool'],arguments,call_id)
            result=transport(step['server'],step['tool'],arguments)
            self.observe(call_id,result)
            self.audit.append({'event':'deterministic_recovery','step':step['id'],'call_id':call_id})
        return {'completed':True,'results':{key:copy.deepcopy(record.value) for key,record in self.results.items()},'audit':copy.deepcopy(self.audit)}
