"""Narrow handler-effect evidence for primitive inputs, not process safety.

Supported handlers only return literal containers/primitive parameters, optionally
branching on membership in a module-local literal set. No attribute calls, I/O,
mutation, arbitrary operators, dynamic globals or decorators are accepted.
Only deployment-owned source may produce these records; MCP advertisements cannot.
"""
import ast,hashlib

TYPES={'str':str,'int':int,'float':float,'bool':bool}

def certify(text,handler):
    try:tree=ast.parse(text)
    except SyntaxError:return None
    functions=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==handler]
    if len(functions)!=1:return None
    fn=functions[0]
    if fn.decorator_list or fn.args.vararg or fn.args.kwarg or fn.args.kwonlyargs or fn.args.posonlyargs:return None
    parameters={}
    for arg in fn.args.args:
        if not isinstance(arg.annotation,ast.Name) or arg.annotation.id not in TYPES:return None
        parameters[arg.arg]=arg.annotation.id
    if not parameters:return None
    # A parameter must not dispatch custom __contains__, __repr__ or formatting.
    # Runtime consumers enforce exact Python primitive types, not isinstance.
    globals_allowed=set()
    for node in tree.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            if isinstance(node.value,(ast.Set,ast.Tuple)) and 0<len(node.value.elts)<=64 and all(isinstance(v,ast.Constant) and type(v.value) in TYPES.values() for v in node.value.elts):
                globals_allowed.add(node.targets[0].id)
    all_nodes=list(ast.walk(tree))
    imported={a.asname or a.name.split('.')[0] for n in all_nodes if isinstance(n,(ast.Import,ast.ImportFrom)) for a in n.names}
    defined={n.name for n in all_nodes if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and n is not fn}
    if (globals_allowed|{handler}) & (imported|defined):return None
    forbidden_names={'exec','eval','globals','locals','setattr','delattr','__import__'}
    if any(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in forbidden_names for n in all_nodes):return None
    if any(isinstance(n,(ast.Import,ast.ImportFrom)) and any(a.name=='*' for a in n.names) for n in all_nodes):return None
    fn_nodes=list(ast.walk(fn))
    for symbol in globals_allowed|{handler}:
        stores=[n for n in all_nodes if isinstance(n,ast.Name) and n.id==symbol and isinstance(n.ctx,(ast.Store,ast.Del))]
        if len(stores)!=(1 if symbol in globals_allowed else 0):return None
        # Literal globals must not be handed to a callable or mutated elsewhere.
        if symbol in globals_allowed and any(isinstance(n,ast.Name) and n.id==symbol and isinstance(n.ctx,ast.Load) and n not in fn_nodes for n in all_nodes):return None
    body=[n for n in fn.body if not (isinstance(n,ast.Expr) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str))]
    if not body:return None
    allowed=(ast.Return,ast.If,ast.Dict,ast.List,ast.Tuple,ast.Set,ast.Constant,ast.Name,ast.Load,ast.Compare,ast.In,ast.NotIn,ast.JoinedStr,ast.FormattedValue)
    nodes=[n for statement in body for n in ast.walk(statement)]
    if any(not isinstance(n,allowed) for n in nodes):return None
    if any(isinstance(n,ast.Name) and n.id not in set(parameters)|globals_allowed for n in nodes):return None
    for n in nodes:
        if isinstance(n,ast.Compare) and not (len(n.ops)==1 and isinstance(n.ops[0],(ast.In,ast.NotIn)) and isinstance(n.left,ast.Name) and n.left.id in parameters and len(n.comparators)==1 and isinstance(n.comparators[0],ast.Name) and n.comparators[0].id in globals_allowed):return None
        if isinstance(n,ast.FormattedValue) and (n.format_spec is not None or n.conversion not in {-1,114,115} or not isinstance(n.value,ast.Name) or n.value.id not in parameters):return None
    # Without a final unconditional return, an unsupported implicit effect path
    # or incomplete execution is not certified.
    if not isinstance(body[-1],ast.Return):return None
    return {'version':1,'handler':handler,'file_sha256':hashlib.sha256(text.encode()).hexdigest(),'parameter_exact_types':parameters,'effect':'no handler side effects in supported AST subset','scope':'handler only; primitive arguments; dependencies/other process code unverified'}

def matches(certificate,arguments):
    if not isinstance(certificate,dict) or certificate.get('version')!=1:return False
    declared=certificate.get('parameter_exact_types')
    return bool(isinstance(declared,dict) and set(declared)==set(arguments) and all(kind in TYPES and type(arguments[key]) is TYPES[kind] for key,kind in declared.items()))
