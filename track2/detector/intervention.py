"""Exact bounded intervention planning and deployment-owned result projection."""
import copy
import hashlib
import itertools
import json
import base64
from urllib.parse import quote
from knowledge_graph import strings, credential_values, candidates


def minimum_intervention(paths, candidates):
    """Minimum positive cost cover of the explicitly enumerated risk paths.

    Exhaustive search is intentional: <=12 candidates and <=32 paths. The
    certificate proves optimality in this finite problem, not unseen behaviors.
    """
    if not 1 <= len(paths) <= 32 or not 1 <= len(candidates) <= 12:
        raise ValueError('Intervention planning budget exceeded')
    names = {p['id'] for p in paths}
    if len(names) != len(paths) or len({c['id'] for c in candidates}) != len(candidates):
        raise ValueError('Duplicate planning identifiers')
    for c in candidates:
        if type(c['cost']) is not int or c['cost'] <= 0 or not set(c['covers']) <= names:
            raise ValueError('Invalid intervention cost or coverage')
    best, explored = None, 0
    for count in range(1, len(candidates)+1):
        for choice in itertools.combinations(candidates, count):
            explored += 1
            if set().union(*(set(c['covers']) for c in choice)) != names:
                continue
            score = (sum(c['cost'] for c in choice), len(choice), tuple(sorted(c['id'] for c in choice)))
            if best is None or score < best[0]: best = (score, choice)
    if best is None: raise ValueError('No complete intervention exists')
    problem = {'paths':paths, 'candidates':candidates}
    return {'selected':[c['id'] for c in best[1]],'cost':best[0][0],
        'covered':sorted(names),'alternatives_examined':explored,'problem':problem,
        'problem_sha256':hashlib.sha256(json.dumps(problem,sort_keys=True).encode()).hexdigest(),
        'scope':'optimal only over supplied observed paths and approved candidate actions'}


class ResultPolicies:
    """No tool text can enable projection or define the retained business fields."""
    def __init__(self, document=None):
        document = document or {'version':1,'tools':[]}
        if type(document.get('version')) is not int or document.get('version') != 1 or not isinstance(document.get('tools'),list):
            raise ValueError('Invalid result policy')
        self.document = copy.deepcopy(document)
        self.digest = hashlib.sha256(json.dumps(document,sort_keys=True).encode()).hexdigest()
        self.tools = {}
        for item in document['tools']:
            identity = (item['server'],item['tool'])
            fields = item['safe_fields']
            if identity in self.tools or not isinstance(fields,dict) or not fields:
                raise ValueError('Invalid result policy tool')
            if any(t not in {'string','integer','boolean','string_array'} for t in fields.values()):
                raise ValueError('Unsupported safe-field type')
            form=item.get('format','structured')
            if form not in {'structured','mcp_json_text'}: raise ValueError('Invalid response format')
            self.tools[identity] = (dict(fields),form)

    def project(self, call, body, planner=True):
        configured = self.tools.get((call.server,call.tool))
        if configured is None or not isinstance(body,dict) or 'error' in body:
            return body, None
        fields,form=configured
        from rules import carries_instruction
        result = body.get('result')
        if form=='mcp_json_text':
            parts=result.get('content') if isinstance(result,dict) else None
            if not isinstance(parts,list) or len(parts)!=1 or not isinstance(parts[0],dict) or parts[0].get('type')!='text':
                return self._deny(body,'approved MCP text structure missing')
            text=parts[0].get('text')
            if not isinstance(text,str) or len(text)>65536:
                return self._deny(body,'approved MCP text budget exceeded')
            try: result=json.loads(text)
            except (ValueError,RecursionError): return self._deny(body,'approved JSON text invalid')
        # Format is deployment-owned. No model or tool can choose it.
        if not isinstance(result,dict):
            return self._deny(body,'approved result structure missing')
        strings(result)
        if not any(carries_instruction(text) for text in strings(result)):
            return body,None
        kept = {key:copy.deepcopy(result[key]) for key in fields if key in result}
        valid = len(kept)==len(fields)
        for key, value in kept.items():
            expected=fields[key]
            valid &= ((type(value) is str) if expected=='string' else
                (type(value) is int) if expected=='integer' else
                (type(value) is bool) if expected=='boolean' else
                (type(value) is list and all(type(x) is str for x in value)))
        valid &= not credential_values(kept) and not any(carries_instruction(t) for t in strings(kept))
        original_secrets=credential_values(result)
        original_forms={form for secret in original_secrets for form in
            [secret,base64.b64encode(secret.encode()).decode(),secret.encode().hex(),quote(secret,safe='')]}
        valid &= not any(text in original_forms for text in candidates(kept))
        if not valid: return self._deny(body,'safe fields missing, invalid or risk-bearing')
        dropped = sorted(set(result)-set(kept))
        if not dropped: return self._deny(body,'no approved separation of risk and business data')
        paths = [{'id':'returned-instruction','stage':'pre-context'}]
        action_candidates=[{'id':'deny-result','cost':10,'covers':['returned-instruction']},
                    {'id':'project-approved-fields','cost':1,'covers':['returned-instruction']}]
        plan=minimum_intervention(paths,action_candidates) if planner else minimum_intervention(paths,action_candidates[:1])
        if 'project-approved-fields' not in plan['selected']:
            response,audit=self._deny(body,'planner disabled; conservative result refusal')
        else:
            response=copy.deepcopy(body); response['result']=kept
            if form=='mcp_json_text': response['result']={'content':[{'type':'text','text':json.dumps(kept)}]}
            audit={'action':'PROJECT','retained':sorted(kept),'removed':dropped,'business_fields_retained':True}
        audit.update(policy_sha256=self.digest,plan=plan,stage='pre-context',
                     original_sha256=hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest())
        return response,audit

    def _deny(self,body,reason):
        plan=minimum_intervention([{'id':'unsafe-result','stage':'pre-context','reason':reason}],
            [{'id':'deny-result','cost':10,'covers':['unsafe-result']}])
        return {'jsonrpc':'2.0','id':body.get('id'),'error':{'code':-32001,
            'message':'unsafe tool result withheld','data':{'reason':reason}}}, {
            'action':'DENY_RESULT','reason':reason,'stage':'pre-context','policy_sha256':self.digest,
            'business_fields_retained':False,'plan':plan,
            'original_sha256':hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest()}
