"""Separate action authority from merely mentioning the affected resource.

Example: viewing payments is not permission to transfer funds. This is a bounded
lexical fallback for deployments without a full bound execution contract. It is
not a universal natural-language intent parser; uncertain tools stay unknown.
"""
import re

INTENTS={
 'payment':r'\b(?:pay|paid|payment|transfer|wire|reimburse|refund|remit|send\s+(?:money|funds|a\s+transaction)|move\s+(?:money|funds))\b|付款|支付|转账|汇款|报销|退款',
 'disclosure':r'\b(?:send|email|mail|forward|share|post|publish|notify|message|upload|reply|respond|broadcast|deliver)\b|发送|邮件|转发|分享|发布|通知|上传|回复',
 'delete':r'\b(?:delete|remove|erase|purge|trash|clear|cancel|revoke|unsubscribe|leave)\b|删除|清空|取消|撤销|退出',
 'update':r'\b(?:update|change|edit|modify|replace|rename|reschedule|correct|set|reset|adjust)\b|修改|更新|更改|重设|重命名',
 'create':r'\b(?:create|add|book|reserve|schedule|invite|subscribe|join|register|arrange|make\s+(?:a\s+)?reservation)\b|创建|添加|预订|预约|邀请|加入|注册',
 'execute':r'\b(?:execute|run|install|launch|compile|deploy|start\s+(?:the\s+)?(?:process|program|service))\b|执行|运行|安装|启动|编译|部署',
}
PATTERNS={key:re.compile(value,re.I) for key,value in INTENTS.items()}
ACTION_PREFIX=re.compile(r'^(send|email|post|publish|upload|forward|share|transfer|pay|schedule|book|reserve|delete|remove|cancel|update|change|edit|set|create|add|invite|execute|run|install)(?:_|$)',re.I)

def effect_class(name, schema):
    match=ACTION_PREFIX.match(name)
    if not match:return None
    verb=match.group(1).lower();keys=set((schema or {}).get('properties',{}))
    if verb in {'transfer','pay'} or (verb in {'send','schedule'} and 'amount' in keys and keys & {'recipient','receiver','iban','account'}):return 'payment'
    if verb in {'send','email','post','publish','upload','forward','share'}:return 'disclosure'
    if verb in {'delete','remove','cancel'}:return 'delete'
    if verb in {'update','change','edit','set'}:return 'update'
    if verb in {'create','add','invite','book','reserve','schedule'}:return 'create'
    return 'execute'

def inspect(s):
    if not s.calls:return []
    from rules import Finding
    from session import tool_meta
    index=len(s.calls)-1;call=s.calls[index];meta=tool_meta().get(call.server+'.'+call.tool) or {}
    code=set(meta.get('code_caps') or [])
    if code and code<={'read_only','fs_read','db_read'}:return []
    kind=effect_class(call.tool,meta.get('schema'))
    if kind is None or PATTERNS[kind].search(s.prompt or ''):return []
    # Delegating unspecified actions to an external checklist has ambiguous
    # authority. A lexical fallback cannot resolve it, so require the stronger
    # deployment contract instead of treating every normal delegation as hostile.
    if re.search(r'\b(?:follow\s+(?:the\s+)?instructions|do\s+(?:all\s+)?the\s+tasks|todo\s+list)\b|按.{0,10}指示|待办清单',s.prompt or '',re.I):return []
    # Trusted task grants are the stronger source of permission. Never override an
    # exact grant with the fallback language classifier.
    if getattr(s,'trusted_task_policy',None):
        from task_policy import permits
        if permits(s.trusted_task_policy,call.server,call.tool,call.arguments):return []
    return [Finding('r11-action-intent','BLOCK',.9,s.instance_id,'Actual action lacks an action request in the original task',
       {'call_index':index,'action_class':kind,'actual_tool':call.server+'.'+call.tool,'authorization_source':'original user prompt; action/resource distinction','method_limit':'lexical fallback, ambiguous implication requires an explicit deployment contract'},['original user task','actual action','refuse before tool execution'])]
