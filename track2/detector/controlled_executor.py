"""Finite executor keeps tool-return data outside control flow, including tool errors."""
import copy
from dataclasses import dataclass
from trusted_plan import PlanDenied,digest,bounded_json


@dataclass(frozen=True)
class DataValue:
    value: object
    source: str
    labels: frozenset


class ControlledExecutor:
    """The transport is supplied by the deployment, never by a request/result.

    Policy owns labels and release permissions. A return cannot remove a label.
    This is a real fixed-plan execution mode, not an unrestricted LLM planner.
    """
    def __init__(self, plans):self.plans=plans

    def execute(self, principal, plan_id, values, transport):
        bound=self.plans.bind(principal,plan_id,values);results={};audit=[]
        for step in bound['plan']['steps']:
            arguments={};sources=[]
            for key,ref in step['arguments'].items():
                kind=next(iter(ref));origin=ref[kind]
                if kind=='literal':value=copy.deepcopy(origin)
                elif kind=='user':value=copy.deepcopy(bound['inputs'][origin])
                else:
                    record=results[origin[0]];value=record.value
                    try:
                        for segment in origin[1:]:value=value[segment]
                    except (KeyError,IndexError,TypeError):raise PlanDenied('declared result field absent')
                    allowed=set(step.get('accept_labels',[]))
                    if not record.labels<=allowed:raise PlanDenied('data label cannot flow to this step')
                    sources.append({'parameter':key,'source':record.source,'labels':sorted(record.labels)})
                    value=copy.deepcopy(value)
                arguments[key]=value
            # The external value is never evaluated, branched on or used as a tool
            # selector. Transport errors stop; they do not request extra actions.
            row={'step':step['id'],'server':step['server'],'tool':step['tool'],
                 'binding_sha256':bound['binding_sha256'],'policy_sha256':bound['policy_sha256'],
                 'arguments_sha256':digest(arguments),'sources':sources}
            result=transport(step['server'],step['tool'],arguments)
            bounded_json(result)
            if isinstance(result,dict) and 'error' in result:raise PlanDenied('approved tool failed; execution stopped')
            labels=frozenset(step.get('result_labels',['untrusted']))
            if not labels or not all(isinstance(x,str) for x in labels):raise PlanDenied('valid deployment result labels required')
            results[step['id']]=DataValue(copy.deepcopy(result),step['id'],labels)
            row.update(result_sha256=digest(result),result_labels=sorted(labels),status='completed');audit.append(row)
        return {'completed':True,'binding_sha256':bound['binding_sha256'],
                'results':{k:copy.deepcopy(v.value) for k,v in results.items()},'audit':audit}
