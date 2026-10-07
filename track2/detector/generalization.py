"""R9: bounded trust-boundary checks, never benchmark labels or tool-name lists.

An external document cannot grant assistant authority. Blocking requires both
an authority claim and an instruction directed at the assistant, not one keyword.
Explicit destinations in the original user request constrain matching arguments.
Ordinary data becomes traceable on egress without declaring all business data secret.
"""
import ast
import hashlib
import json
import re

AUTHORITY = re.compile(
    r"(?:\b(?:system|developer|assistant|user)\s*(?:message|instruction|prompt|:)|"
    r"\b(?:i am|this is|from|on behalf of)\s+(?:the\s+)?(?:user|system|developer)|"
    r"\b(?:ignore|disregard|override|supersede)\b.{0,100}\b(?:instruction|request|prompt)|"
    r"\b(?:important|new|updated|additional)\s+instructions?\b|"
    r"<\|(?:im_start|system|user)|\[/?(?:INST|SYSTEM)\]|"
    r"系统指令|开发者指令|忽略.{0,20}(?:指令|要求)|我是用户)", re.I | re.S)
DIRECTIVE = re.compile(
    r"(?:\b(?:you|assistant|agent|model)\s+(?:must|should|need to|have to|will)|"
    r"\b(?:please|must|first|before|instead|now|then)\b.{0,100}"
    r"\b(?:call|use|send|transfer|pay|delete|execute|run|upload|forward|share|change)|"
    r"\b(?:call|invoke)\s+(?:the\s+)?(?:function|tool)|"
    r"(?:请|必须|先|立即).{0,50}(?:调用|转账|发送|删除|执行|上传))", re.I | re.S)
EMAIL = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
DESTINATION = re.compile(r"(?:^|_)(?:recipient|receiver|beneficiary|to|email|iban|destination)(?:$|_)", re.I)
SENSITIVE = re.compile(r"\b(?:passport|social security|ssn|credit card|private key|medical record)\b|身份证|病历|护照", re.I)


def views(value):
    """Inspect JSON/Python literal string leaves within fixed byte/node budgets.

    No YAML constructors, executable expressions, or recursive regex decoding.
    Python literal decoding covers inert historical transport representations.
    """
    stack = [value]; result = []; count = 0; budget = 65536
    while stack and count < 512 and budget > 0:
        node = stack.pop(); count += 1
        if isinstance(node, str):
            text = node[:budget]; budget -= len(text); result.append(text)
            if text.lstrip().startswith(('{', '[')) and len(text) < 32768:
                try: parsed = json.loads(text)
                except (ValueError, RecursionError):
                    try: parsed = ast.literal_eval(text)
                    except (ValueError, SyntaxError, RecursionError, MemoryError): parsed = None
                if isinstance(parsed, (dict, list, tuple)): stack.append(parsed)
        elif isinstance(node, dict): stack.extend(list(node.values())[:512])
        elif isinstance(node, (list, tuple)): stack.extend(node[:512])
    return result


def injection_evidence(value):
    for text in views(value):
        authority = AUTHORITY.search(text)
        if authority:
            # Require local conjunction to avoid joining unrelated long sections.
            start = max(0, authority.start()-200)
            window = text[start:authority.end()+1200]
            directive = DIRECTIVE.search(window)
            if directive:
                return {'authority': authority.group(0), 'directive': directive.group(0),
                        'source_sha256': hashlib.sha256(text.encode()).hexdigest(),
                        'authority_offset': authority.start(), 'view': 'bounded string leaf'}
    return None


def destination_ids(text):
    return {x.casefold() for x in EMAIL.findall(text)} | {x.casefold() for x in IBAN.findall(text)}


def rule_task_objects(s):
    from rules import Finding
    from session import CAP_NET, consequences_of
    if not s.calls: return []
    index = len(s.calls)-1; call = s.calls[index]; out = []
    prompt = s.prompt or ''
    # A recipient mentioned for one subtask cannot constrain another subtask.
    # Free-text binding is decisive only for an unambiguous single action.
    # Multi-action tasks use the existing deployment-owned task policy instead.
    actions = re.findall(r'\b(?:send|forward|transfer|pay|refund|update|delete|share|upload|publish)\b|发送|转发|转账|付款|退款|更新|删除|上传', prompt, re.I)
    trusted = destination_ids(prompt) if len(actions) == 1 else set()
    actual = set()
    for key, value in call.arguments.items():
        if DESTINATION.search(key):
            for text in views(value): actual.update(destination_ids(text))
    if trusted and actual and not actual.issubset(trusted) and (
            CAP_NET in call.caps or consequences_of(call.tool) & {'financial', 'disclosure'}):
        out.append(Finding('r9-task-object', 'BLOCK', .99, s.instance_id,
            'Destination conflicts with explicit original user request',
            {'call_index': index, 'trusted_destinations': sorted(trusted),
             'requested_destinations': sorted(actual), 'authorization_source': 'original user prompt'},
            ['trusted user task', 'actual destination argument', 'refuse current call']))
    # Trace actual copied business text; require a sensitivity label before refusal.
    # No universal claim: paraphrases/encoding and unnamed sensitive records escape.
    if CAP_NET in call.caps:
        args = '\n'.join(views(call.arguments))
        for source_index, source in enumerate(s.calls[:index]):
            if not source.ok or source.result is None: continue
            for text in views(source.result):
                text = text.strip()
                if len(text) >= 40 and text in args and SENSITIVE.search(text):
                    if not destination_ids(args).issubset(destination_ids(s.prompt or '')):
                        out.append(Finding('r9-business-flow', 'BLOCK', .95, s.instance_id,
                            'Sensitive business text copied to a destination absent from original task',
                            {'call_index': index, 'source_call_index': source_index,
                             'source_sha256': hashlib.sha256(text.encode()).hexdigest(),
                             'matched_bytes': len(text.encode()), 'sensitivity_basis': SENSITIVE.search(text).group(0)},
                            ['observed successful return', 'exact copied business text', 'unapproved destination']))
                        return out
    return out
