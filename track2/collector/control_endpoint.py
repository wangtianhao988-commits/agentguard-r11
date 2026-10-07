"""Authenticated ASGI endpoint for pre-approved fixed control plans."""
import json
from datetime import datetime,timezone
from dataclasses import asdict,is_dataclass
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from trusted_plan import PlanDenied
from controlled_executor import ControlledExecutor


class ControlEndpoint:
    def __init__(self,plans,authenticate,transport,record,proposer=None):
        self.executor=ControlledExecutor(plans);self.authenticate=authenticate;self.transport=transport;self.record=record
        self.model_executor=None
        if proposer is not None:
            from model_controlled_executor import ModelControlledExecutor
            self.model_executor=ModelControlledExecutor(plans,proposer)

    async def __call__(self,scope,receive,send):
        model_mode=scope.get('path')=='/agentguard/execute-model'
        if scope.get('method')!='POST' or scope.get('path') not in {'/agentguard/execute','/agentguard/execute-model'} or (model_mode and self.model_executor is None):
            return await JSONResponse({'error':'route unavailable'},status_code=404)(scope,receive,send)
        request=Request(scope,receive)
        try:
            identity=self.authenticate(request.headers.get('authorization'))
            actor=asdict(identity) if is_dataclass(identity) else dict(identity)
            if not isinstance(actor.get('sub'),str) or not actor['sub']:raise ValueError('authenticated subject missing')
        except Exception:
            return await JSONResponse({'error':'authentication required'},status_code=401)(scope,receive,send)
        try:
            raw=bytearray()
            async for chunk in request.stream():
                raw.extend(chunk)
                if len(raw)>131072:return await JSONResponse({'error':'request too large'},status_code=413)(scope,receive,send)
            body=json.loads(raw)
            allowed={'plan_id','inputs','prompt'} if model_mode else {'plan_id','inputs'}
            if not isinstance(body,dict) or not {'plan_id','inputs'}<=set(body) or not set(body)<=allowed:raise PlanDenied('only plan selection and declared inputs are accepted')
            if model_mode and 'prompt' in body and (not isinstance(body['prompt'],str) or len(body['prompt'])>8192):raise PlanDenied('bounded model prompt required')
            self.record('R10_control_request',{'principal':actor['sub'],'plan_id':body['plan_id'],'inputs':body['inputs'],'ts':datetime.now(timezone.utc).isoformat()})
            def execute():
                def tool(server,name,args):return self.transport(actor,server,name,args)
                if model_mode:return self.model_executor.execute(actor['sub'],body['plan_id'],body['inputs'],tool,body.get('prompt'))
                return self.executor.execute(actor['sub'],body['plan_id'],body['inputs'],tool)
            result=await run_in_threadpool(execute)
            self.record('R10_control_completed',{'principal':actor['sub'],'plan_id':body['plan_id'],**result})
            response=JSONResponse(result)
        except (PlanDenied,ValueError,KeyError,TypeError) as error:
            self.record('R10_control_denied',{'principal':actor['sub'],'reason':str(error)})
            response=JSONResponse({'error':'control plan denied','reason':str(error)},status_code=403)
        except Exception as error:
            self.record('R10_control_error',{'principal':actor['sub'],'error':type(error).__name__})
            response=JSONResponse({'error':'approved tool unavailable'},status_code=502)
        return await response(scope,receive,send)
