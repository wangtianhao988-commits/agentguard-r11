"""Optional single-worker ASGI/requests integration of the existing detector.

Set GUARD_APP_IMPORT to the original ASGI application (module:attribute). Target
source is imported unchanged. The requests hook sees prepared bytes, judges MCP
calls before sending and joins actual returned values by a unique call ID. The
HTTP gateway remains available for framework traffic and other client SDKs.
"""
import asyncio
import contextvars
import importlib
import hashlib
import json
import os
import time
from urllib.parse import urlsplit

import requests
from starlette.requests import Request
from starlette.responses import JSONResponse
import gateway as core
from native_stack import capture as capture_native_stack

_CONTEXT = contextvars.ContextVar('agentguard_request', default=None)
_ORIGINAL_SEND = requests.sessions.Session.send
from pooled_transport import BorrowedPools
_POOLS=BorrowedPools(_ORIGINAL_SEND)
_LOOP = None
_SERVERS = {}
_cpu_ns = 0

try:
    with open(core.INVENTORY_PATH, encoding='utf-8') as source:
        inventory = json.load(source)
    for asset in inventory.get('asset_graph', {}).get('assets', []):
        if asset.get('kind') == 'mcp_server':
            endpoint = asset.get('attributes', {}).get('endpoint')
            if endpoint:
                _SERVERS[endpoint.rstrip('/')] = asset['name']
except (OSError, ValueError, KeyError):
    raise RuntimeError('In-process integration requires a readable MCP inventory')

def _upstream_send(session,request,**kwargs):
    permitted=request.url.rstrip('/') in _SERVERS or request.url.rstrip('/')==os.environ.get('LLM_BASE','http://llm-stub:8000/v1').rstrip('/')+'/chat/completions'
    if permitted and os.environ.get('GUARD_CONNECTION_POOL','1')=='1':return _POOLS.send(session,request,**kwargs)
    return _ORIGINAL_SEND(session,request,**kwargs)


def _capture(rid, context, action):
    if core.CAPTURE_ON == 'off' or (action == 'ALLOW' and core.CAPTURE_ON != 'always'):
        return
    # This hook executes inside the real application worker. Reading its current
    # frames is exact at the interception point and avoids an HTTP exchange plus
    # a py-spy process. The framework proxy keeps its external stack capture.
    try:
        payload = capture_native_stack()
        core._record('code_stack', {'obs': 'S', 'rid': rid, 'ts': core._now(),
                                   'capture_target': 'protected-agent',
                                   'stage': 'pre-tool-send', **context, **payload})
    except Exception as error:
        core._record('code_stack', {'obs': 'S', 'rid': rid, 'ts': core._now(),
                                   **context, 'error': type(error).__name__})


def _send(self, request, **kwargs):
    global _cpu_ns
    context = _CONTEXT.get()
    if context is None:
        return _upstream_send(self, request, **kwargs)
    started = time.thread_time_ns()
    raw = request.body
    if not isinstance(raw, (str, bytes)):
        _cpu_ns += time.thread_time_ns() - started
        return _upstream_send(self, request, **kwargs)
    try:
        from json_codec import loads
        body = loads(raw)
    except (ValueError, TypeError):
        _cpu_ns += time.thread_time_ns() - started
        return _upstream_send(self, request, **kwargs)
    if not isinstance(body, dict):
        _cpu_ns += time.thread_time_ns() - started
        return _upstream_send(self, request, **kwargs)
    headers = {k.lower(): v for k, v in request.headers.items()
               if k.lower() in {'authorization', 'x-trace-id', 'x-instance-id', 'x-acting-user'}}
    # Bind detection state to the inbound request, rather than accepting a tool's
    # self-reported trace or sharing identities between callers with the same trace.
    sid = context['state_id']
    external_sid = context['sid']
    headers['x-trace-id'] = external_sid
    if not context['observed']:
        # The supported target validates authentication before its synchronous
        # handler invokes requests. Rejected requests therefore cannot seed state.
        core.GUARD.observe_run(sid, context['headers'], context['body'])
        context['observed'] = True
        context['policy'] = core.GUARD.policy_binding(sid)
    rid = core._rid()
    is_mcp = body.get('method') in {'tools/call', 'tools/list', 'initialize'}
    if not is_mcp:
        if urlsplit(request.url).path.endswith('/chat/completions') and isinstance(body.get('messages'), list):
            messages = body['messages']
            core.GUARD.observe_skill_catalog(sid, messages)
            core._record('B_llm_request', {'obs': 'B', 'rid': rid, 'ts': core._now(),
                'headers': headers, 'n_messages': len(messages),
                'roles': [m.get('role') for m in messages if isinstance(m, dict)],
                'tools': [t.get('function', {}).get('name') for t in body.get('tools', [])],
                'messages': messages})
        _cpu_ns += time.thread_time_ns() - started
        return _upstream_send(self, request, **kwargs)
    server = _SERVERS.get(request.url.rstrip('/')) or (urlsplit(request.url).hostname or 'unknown')
    params = body.get('params') or {}
    tool = params.get('name')
    # Only an omitted arguments member means an empty object. Explicit null,
    # false, strings and arrays must reach the guard's shape validation intact.
    arguments = params.get('arguments', {})
    core._record('C_mcp_call', {'obs': 'C', 'rid': rid, 'ts': core._now(),
        'server': server, 'headers': headers, 'jsonrpc_method': body.get('method'),
        'tool': tool, 'arguments': arguments, 'body': body,
        **({'trusted_task_policy': context['policy']} if context.get('policy') is not None else {})})
    decision = None
    if body.get('method') == 'tools/call' and tool:
        decision = core.GUARD.check_tool_call(sid, server, tool, arguments, call_id=rid)
        _capture(rid, {'point': 'mcp', 'server': server, 'tool': tool, 'session_id': external_sid}, decision.action)
        core._record('guard_decision', {'obs': 'G', 'rid': rid, 'ts': core._now(),
            'point': 'mcp', 'server': server, 'tool': tool, 'integration': 'inprocess',
            **decision.to_json(), 'session_id': external_sid})
    _cpu_ns += time.thread_time_ns() - started
    if decision is not None and decision.blocked:
        response = requests.Response()
        response.status_code = 200
        response.headers['Content-Type'] = 'application/json'
        response.request = request
        response.url = request.url
        response._content = json.dumps({'jsonrpc': '2.0', 'id': body.get('id'),
            'error': {'code': -32000, 'message': 'blocked by agent guard',
                      'data': {'rid': rid, 'reason': decision.reason}}}).encode()
        return response
    network_started = time.perf_counter()
    response = _upstream_send(self, request, **kwargs)
    started = time.thread_time_ns()
    try:
        from json_codec import response_json
        result = response_json(response)
    except ValueError:
        result = {'__raw__': response.text[:4000]}
    raw_result=result
    audit=None
    intervention_started=time.perf_counter()
    if decision is not None:
        result,audit=core.GUARD.observe_tool_result(sid, rid, result, ok=response.status_code < 400)
    if audit is not None:
        core._record('C_raw_response',{'obs':'C_RAW','rid':rid,'ts':core._now(),'body':raw_result,
            'session_id':external_sid,'server':server,'tool':tool})
        core._record('result_intervention',{'obs':'I','rid':rid,'ts':core._now(),'session_id':external_sid,
            'server':server,'tool':tool,**audit})
        core._record('guard_decision',{'obs':'G','rid':rid,'ts':core._now(),'session_id':external_sid,
            'point':'result','stage':'pre-context','action':'BLOCK','server':server,'tool':tool,
            'intervention_action':audit['action'],'findings':[audit['finding']],
            'reason':'unsafe result isolated before context',
            'latency_us':round((time.perf_counter()-intervention_started)*1e6,1)})
        _capture(rid,{'point':'result','stage':'pre-context','server':server,'tool':tool,'session_id':external_sid},'BLOCK')
        response._content=json.dumps(result).encode()
        response.headers.pop('Content-Length',None)
    core._record('C_response', {'obs': 'C', 'rid': rid, 'ts': core._now(),
        'upstream': request.url, 'status': response.status_code,
        'latency_ms': (time.perf_counter()-network_started)*1000, 'body': result,'intervened':audit is not None})
    _cpu_ns += time.thread_time_ns() - started
    return response


class GuardApplication:
    def __init__(self, target):
        self.target = target
        self.control = None
        policy_path=os.environ.get('GUARD_R10_CONTROL_POLICY_PATH')
        if policy_path:
            from trusted_plan import ControlPlans,PlanDenied
            from control_endpoint import ControlEndpoint
            from session import Session,ToolCall,_unwrap_tool_result
            from rules import rule_scope_violation
            plans=ControlPlans(json.loads(open(policy_path,encoding='utf-8').read()))
            auth_module,auth_attribute=os.environ['GUARD_R10_AUTH_IMPORT'].split(':',1)
            authenticate=getattr(importlib.import_module(auth_module),auth_attribute)
            declared={a['name'] for a in inventory.get('asset_graph',{}).get('assets',[]) if a.get('kind')=='tool'}
            for plan in plans._plans.values():
                for step in plan['steps']:
                    if step['server']+'.'+step['tool'] not in declared:raise ValueError('control plan refers to undeclared tool')
            endpoints={server:endpoint for endpoint,server in _SERVERS.items()}
            def transport(actor,server,tool,args):
                rid=core._rid();call=ToolCall(server,tool,args)
                state=Session('control-'+rid,identity=actor,calls=[call])
                if any(f.severity=='BLOCK' for f in rule_scope_violation(state)):raise PlanDenied('control plan exceeds accepted identity scope')
                core._record('R10_control_tool',{'rid':rid,'principal':actor['sub'],'server':server,'tool':tool,'arguments':args,
                    'stack':capture_native_stack()})
                # URI selection remains owned by trusted inventory, redirects disabled.
                response=requests.post(endpoints[server],json={'jsonrpc':'2.0','id':rid,'method':'tools/call','params':{'name':tool,'arguments':args}},timeout=3,allow_redirects=False)
                if response.status_code!=200 or len(response.content)>131072:raise PlanDenied('approved endpoint returned unsupported response')
                raw=response.json()
                if not isinstance(raw,dict) or 'error' in raw:raise PlanDenied('approved tool refused call')
                result=_unwrap_tool_result(raw)
                if isinstance(result,str):
                    try:result=json.loads(result)
                    except ValueError:pass
                return result
            proposer=None
            if os.environ.get('GUARD_R11_MODEL_URL'):
                from model_proposer import LocalModelProposer
                proposer=LocalModelProposer(os.environ['GUARD_R11_MODEL_URL'],os.environ.get('GUARD_R11_MODEL_API_KEY'))
            self.control=ControlEndpoint(plans,authenticate,transport,core._record,proposer)

    async def __call__(self, scope, receive, send):
        global _LOOP, _cpu_ns
        if scope['type'] == 'lifespan':
            async def observed_receive():
                global _LOOP
                event = await receive()
                if event['type'] == 'lifespan.startup':
                    _LOOP = asyncio.get_running_loop()
                    requests.sessions.Session.send = _send
                    await core._start_evidence_sweeper()
                elif event['type'] == 'lifespan.shutdown':
                    _POOLS.close()
                    requests.sessions.Session.send = _ORIGINAL_SEND
                    if core._SWEEPER_TASK is not None:
                        core._SWEEPER_TASK.cancel()
                    core.GUARD.close()
                    core.STORE.close()
                    await core.CLIENT.aclose()
                return event
            return await self.target(scope, observed_receive, send)
        if scope['type'] != 'http':
            return await self.target(scope, receive, send)
        if scope['path'] in {'/agentguard/execute','/agentguard/execute-model'} and scope['method']=='POST' and self.control is not None:
            return await self.control(scope,receive,send)
        if scope['path'] == '/agentguard/health':
            response = JSONResponse({'integration': 'inprocess', 'guard': core.GUARD.snapshot(),
                'task_policy_enabled': core.GUARD.task_policies is not None,
                'trusted_control_plan_enabled':self.control is not None,
                'tool_profile_loaded': core.N_TOOLS_LOADED, 'partial_guard_thread_cpu_ns': _cpu_ns,
                'records_dropped': core.STORE.dropped()})
            return await response(scope, receive, send)
        if scope['method'] != 'POST' or scope['path'] not in {'/run', '/login'}:
            return await self.target(scope, receive, send)
        # Read once, then replay the same raw body to the original ASGI application.
        request = Request(scope, receive)
        raw = await request.body()
        started = time.thread_time_ns()
        try:
            body = json.loads(raw)
        except ValueError:
            body = {}
        headers = dict(request.headers)
        sid = headers.get('x-trace-id') or headers.get('x-instance-id') or core._rid()
        if not headers.get('x-trace-id'):
            scope['headers'] = list(scope['headers']) + [(b'x-trace-id', sid.encode('latin-1'))]
            headers['x-trace-id'] = sid
        core._record('A_agent_ingress', {'obs': 'A', 'rid': core._rid(), 'ts': core._now(),
            'path': scope['path'], 'headers': headers, 'body': body})
        principal_partition = hashlib.sha256(headers.get('authorization', '').encode('utf-8')).hexdigest()
        token = _CONTEXT.set({'sid': sid, 'state_id': sid + ':' + principal_partition,
            'headers': headers, 'body': body if isinstance(body, dict) else {}, 'observed': False})
        _cpu_ns += time.thread_time_ns() - started
        consumed = False
        async def replay_body():
            nonlocal consumed
            if not consumed:
                consumed = True
                return {'type': 'http.request', 'body': raw, 'more_body': False}
            return await receive()
        try:
            return await self.target(scope, replay_body, send)
        finally:
            _CONTEXT.reset(token)


module, attribute = os.environ['GUARD_APP_IMPORT'].split(':', 1)
app = GuardApplication(getattr(importlib.import_module(module), attribute))
diagnostic = os.getenv('GUARD_AUTH_DIAGNOSTIC_IMPORT')
if diagnostic:
    from auth_diagnostic import instrument
    diagnostic_module, diagnostic_attribute = diagnostic.split(':', 1)
    owner = importlib.import_module(diagnostic_module)
    def record_auth_rejection(evidence):
        context = _CONTEXT.get() or {}
        core._record('auth_rejection', {'obs': 'AUTH', 'rid': core._rid(),
                     'ts': core._now(), 'session_id': context.get('sid'), **evidence})
    setattr(owner, diagnostic_attribute,
            instrument(getattr(owner, diagnostic_attribute), record_auth_rejection))
