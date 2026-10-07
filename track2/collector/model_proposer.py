"""Deployment-owned OpenAI-compatible model transport; bounded, no redirects."""
import requests
from trusted_plan import PlanDenied,bounded_json

class LocalModelProposer:
    def __init__(self, base_url, api_key=None):
        self.url=base_url.rstrip('/')+'/v1/chat/completions'
        self.headers={'Authorization':'Bearer '+api_key} if api_key else {}
    def __call__(self,messages,tools):
        request={'model':'local','messages':messages,'tools':tools,'parallel_tool_calls':False,'temperature':0,'seed':42,'max_tokens':256,'chat_template_kwargs':{'enable_thinking':False}}
        with requests.post(self.url,json=request,headers=self.headers,timeout=(3,30),allow_redirects=False,stream=True) as response:
            if response.status_code!=200:raise PlanDenied('model proposal unavailable')
            raw=bytearray()
            for chunk in response.iter_content(8192):
                raw.extend(chunk)
                if len(raw)>131072:raise PlanDenied('model response byte budget exceeded')
        import json
        value=json.loads(raw);bounded_json(value)
        return value['choices'][0]['message']
