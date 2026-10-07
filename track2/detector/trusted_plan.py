"""Deployment-owned finite control plans. No eval, branches or returned tool names."""
import copy
import hashlib
import json


class PlanDenied(ValueError):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()


def bounded_json(value, max_nodes=4096, max_bytes=131072):
    """Reject oversized/non-JSON values before deepcopy or audit serialization.

    An external transport can return nested/cyclic objects even when its HTTP
    byte limit is satisfied. Iterative validation also rejects bool-as-number,
    non-finite floats and custom Python objects at the trust boundary.
    """
    import math
    stack=[(value,0)];nodes=0;bytes_used=0
    while stack:
        node,depth=stack.pop();nodes+=1
        if nodes>max_nodes or depth>32:raise PlanDenied('JSON structure budget exceeded')
        if type(node) is dict:
            if len(node)>max_nodes-nodes:raise PlanDenied('JSON structure budget exceeded')
            for key,item in node.items():
                if type(key) is not str:raise PlanDenied('JSON keys must be strings')
                bytes_used+=len(key.encode('utf-8'));stack.append((item,depth+1))
        elif type(node) is list:
            if len(node)>max_nodes-nodes:raise PlanDenied('JSON structure budget exceeded')
            stack.extend((item,depth+1) for item in node)
        elif type(node) is str:bytes_used+=len(node.encode('utf-8'))
        elif type(node) is float:
            if not math.isfinite(node):raise PlanDenied('finite JSON numbers required')
        elif type(node) is int:
            if node.bit_length()>4096:raise PlanDenied('JSON integer budget exceeded')
        elif node is not None and type(node) is not bool:raise PlanDenied('plain JSON values required')
        if bytes_used>max_bytes:raise PlanDenied('JSON byte budget exceeded')
    return value


def validate_spec(spec):
    if not isinstance(spec,dict) or spec.get('type') not in {'string','integer','number','boolean','object','array'}:raise ValueError('supported input schema required')
    limit=spec.get('max_length',4096)
    if type(limit) is not int or not 0<=limit<=131072:raise ValueError('bounded input length required')
    if 'enum' in spec:
        if not isinstance(spec['enum'],list) or not 1<=len(spec['enum'])<=256:raise ValueError('bounded input enumeration required')
        try:
            for value in spec['enum']:validate_value(value,{k:v for k,v in spec.items() if k!='enum'})
        except PlanDenied as error:raise ValueError('invalid enumerated input') from error


def validate_value(value, spec):
    bounded_json(value)
    types={'string':str,'integer':int,'number':(int,float),'boolean':bool,'object':dict,'array':list}
    expected=types.get(spec.get('type'))
    if expected is None or not isinstance(value,expected) or (isinstance(value,bool) and spec['type'] in {'integer','number'}):
        raise PlanDenied('input type mismatch')
    if isinstance(value,(int,float)) and not isinstance(value,bool):
        import math
        if not math.isfinite(value) or value<spec.get('min',float('-inf')) or value>spec.get('max',float('inf')):raise PlanDenied('input range exceeded')
    if isinstance(value,(str,list,dict)) and len(value)>spec.get('max_length',4096):raise PlanDenied('input length exceeded')
    if 'enum' in spec and not any(type(value) is type(v) and value==v for v in spec['enum']):raise PlanDenied('value absent from approved enumeration')
    return copy.deepcopy(value)


class ControlPlans:
    """Policy files are read-only administrator input; caller supplies values only."""
    def __init__(self, document):
        if not isinstance(document,dict) or type(document.get('version')) is not int or document['version']!=1:raise ValueError('control policy version 1 required')
        bounded_json(document,max_nodes=32768,max_bytes=262144)
        plans=document.get('plans')
        if not isinstance(plans,list) or len(plans)>128:raise ValueError('bounded plans required')
        self.document=copy.deepcopy(document); self.sha256=digest(document); self._plans={}
        for plan in plans:
            if not isinstance(plan,dict):raise ValueError('plan object required')
            pid=plan.get('id');steps=plan.get('steps');seen=set()
            if not isinstance(pid,str) or not pid or pid in self._plans:raise ValueError('unique plan ID required')
            if not isinstance(plan.get('principals'),list) or not plan['principals'] or not all(isinstance(x,str) and x for x in plan['principals']) or not isinstance(plan.get('inputs'),dict):raise ValueError('principal/input declaration required')
            if len(plan['inputs'])>64:raise ValueError('bounded inputs required')
            for key,spec in plan['inputs'].items():
                if not isinstance(key,str) or not key:raise ValueError('input name required')
                validate_spec(spec)
            if not isinstance(steps,list) or not 1<=len(steps)<=32:raise ValueError('1..32 fixed steps required')
            for step in steps:
                if not isinstance(step,dict):raise ValueError('step object required')
                for label_key in ['result_labels','accept_labels']:
                    labels=step.get(label_key,['untrusted'] if label_key=='result_labels' else [])
                    if not isinstance(labels,list) or len(labels)>32 or (label_key=='result_labels' and not labels) or not all(isinstance(x,str) and x for x in labels):raise ValueError('valid deployment labels required')
                if not all(isinstance(step.get(k),str) and step[k] for k in ['id','server','tool']) or step['id'] in seen:raise ValueError('invalid fixed tool step')
                args=step.get('arguments');data=step.get('data_arguments',[])
                if not isinstance(args,dict) or len(args)>64 or not isinstance(data,list) or not set(data)<=set(args):raise ValueError('bounded argument declarations required')
                # Only explicitly declared DATA arguments can depend on prior returns.
                for key,ref in args.items():
                    if not isinstance(ref,dict) or len(ref)!=1:raise ValueError('one literal/user/result origin per argument')
                    kind=next(iter(ref));value=ref[kind]
                    if kind=='user' and value not in plan['inputs']:raise ValueError('undeclared user input')
                    if kind=='result':
                        if key not in data or key not in {'body','text','content','message','note','summary','description'} or not isinstance(value,list) or not value or value[0] not in seen:raise ValueError('external value cannot control execution')
                        if not all(isinstance(x,(str,int)) and not isinstance(x,bool) for x in value):raise ValueError('fixed result path required')
                    elif kind not in {'literal','user'}:raise ValueError('unsupported expression origin')
                seen.add(step['id'])
            self._plans[pid]=copy.deepcopy(plan)

    def bind(self, principal, plan_id, values):
        plan=self._plans.get(plan_id)
        if plan is None or principal not in plan['principals']:raise PlanDenied('principal cannot select this plan')
        if not isinstance(values,dict) or set(values)!=set(plan['inputs']):raise PlanDenied('exact user input keys required')
        inputs={key:validate_value(values[key],spec) for key,spec in plan['inputs'].items()}
        return {'principal':principal,'plan':copy.deepcopy(plan),'inputs':inputs,'policy_sha256':self.sha256,
                'binding_sha256':digest({'principal':principal,'plan':plan,'inputs':inputs,'policy':self.sha256})}
