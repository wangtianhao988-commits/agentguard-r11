"""Narrow positive source profiles; unknown/dynamic constructs remain unverified.

These profiles never establish whole-process safety. They distinguish a concrete
local handler or entrypoint from capabilities inferred from its advertisements.
"""
import ast
from pathlib import Path


def enrich(graph, root):
    root = Path(root)
    for path in (root / 'mcp').rglob('*.py'):
        try:
            tree = ast.parse(path.read_text(encoding='utf-8'))
        except (OSError, SyntaxError, UnicodeError):
            continue
        from codecap import _tool_registrations
        handlers = _tool_registrations(tree)
        functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
        imported = set()
        wildcard_import = False
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    imported.add(alias.asname or alias.name.split('.')[0])
                    wildcard_import |= alias.name == '*'
        defined = {node.name for node in tree.body
                   if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
        namespace_mutation = any(
            (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
             and node.func.id in {'exec', 'eval', 'globals', 'locals', 'setattr', 'delattr'})
            or (isinstance(node, (ast.Attribute, ast.Subscript))
                and isinstance(node.ctx, (ast.Store, ast.Del)))
            for node in ast.walk(tree))
        for name, handler in handlers.items():
            fn = functions.get(handler)
            if fn is None or fn.decorator_list or len(fn.body) != 1 or not isinstance(fn.body[0], ast.Return):
                continue
            args = {a.arg for a in fn.args.args}
            # A symbol spelled len need not be the builtin: imports, definitions
            # and a parameter can all replace it with a network-capable callable.
            if wildcard_import or namespace_mutation or 'builtins' in imported or 'len' in args | imported | defined:
                continue
            allowed = (ast.Return, ast.Dict, ast.List, ast.Tuple, ast.Constant,
                       ast.Name, ast.Load, ast.Call)
            nodes = list(ast.walk(fn.body[0]))
            # Only literal containers, argument references and builtin len(arg).
            # No attribute access, arbitrary call, operator dispatch or side effects.
            if any(not isinstance(n, allowed) for n in nodes):
                continue
            if any(isinstance(n, ast.Name) and n.id not in args | {'len'} for n in nodes):
                continue
            if any(isinstance(n, ast.Call) and (not isinstance(n.func, ast.Name)
                    or n.func.id != 'len' or len(n.args) != 1 or n.keywords
                    or not isinstance(n.args[0], ast.Name) or n.args[0].id not in args) for n in nodes):
                continue
            if any(isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store) for n in ast.walk(tree)):
                # A module may shadow len or replace handlers; keep uncertainty.
                if any(isinstance(n, ast.Name) and n.id in {'len', handler}
                       and isinstance(n.ctx, ast.Store) for n in ast.walk(tree)):
                    continue
            for a in graph.assets.values():
                if a.kind == 'tool' and a.name.endswith('.' + name):
                    server_dir = a.attributes.get('server', '').replace('-', '_')
                    if server_dir in path.parts:
                        a.attributes['code_profile_pure_return'] = {
                            'file': str(path.relative_to(root)), 'handler': handler,
                            'line': fn.lineno, 'scope': 'handler-only; runtime Python primitive inputs'}
    for a in graph.assets.values():
        if a.kind not in {'service', 'agent', 'datastore', 'mcp_server'}:
            continue
        command = a.attributes.get('entrypoint') or []
        targets = [x.split(':')[0] for x in command if isinstance(x, str) and ':' in x
                   and not x.startswith(('/', 'http'))]
        original = (a.attributes.get('env') or {}).get('GUARD_APP_IMPORT')
        if original:
            targets.append(original.split(':', 1)[0])
        for module in targets:
            matches = list(root.glob('*/' + module.replace('.', '/') + '.py'))
            if len(matches) != 1:
                continue
            path = matches[0]
            try:
                tree = ast.parse(path.read_text(encoding='utf-8'))
            except (OSError, SyntaxError, UnicodeError):
                continue
            keys = set()
            for n in ast.walk(tree):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in {'getenv', 'get'}:
                    if n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str):
                        keys.add(n.args[0].value)
            functions = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
            guard_symbols = {'Depends', 'Header', 'HTTPException'}
            canonical = {alias.asname or alias.name for node in tree.body
                         if isinstance(node, ast.ImportFrom) and node.module == 'fastapi'
                         for alias in node.names if alias.name in guard_symbols and not alias.asname}
            rebound = {node.id for node in ast.walk(tree)
                       if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)}
            rebound |= {node.name for node in tree.body
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
            rebound |= {alias.asname or alias.name for node in tree.body
                        if isinstance(node, (ast.Import, ast.ImportFrom))
                        for alias in node.names
                        if not (isinstance(node, ast.ImportFrom) and node.module == 'fastapi'
                                and alias.name in guard_symbols and not alias.asname)}
            symbols_bound = guard_symbols <= canonical and not guard_symbols & rebound
            dependency_evidence = []
            for fn in functions.values():
                for default in fn.args.defaults + fn.args.kw_defaults:
                    if not isinstance(default, ast.Call) or not isinstance(default.func, ast.Name) or default.func.id != 'Depends':
                        continue
                    if not default.args or not isinstance(default.args[0], ast.Name):
                        continue
                    dep = functions.get(default.args[0].id)
                    if dep is None:
                        continue
                    defaults = dict(zip([p.arg for p in dep.args.args[-len(dep.args.defaults):]], dep.args.defaults))
                    defaults.update(zip([p.arg for p in dep.args.kwonlyargs], dep.args.kw_defaults))
                    header_names = {name for name, value in defaults.items()
                        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                        and value.func.id == 'Header'}
                    statements = [node for node in dep.body if not (
                        isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, str))]
                    if not statements or not isinstance(statements[0], ast.If):
                        continue
                    branch = statements[0]
                    condition = branch.test.values[0] if isinstance(branch.test, ast.BoolOp) and isinstance(branch.test.op, ast.Or) else branch.test
                    missing_header = (isinstance(condition, ast.UnaryOp) and isinstance(condition.op, ast.Not)
                        and isinstance(condition.operand, ast.Name) and condition.operand.id in header_names)
                    if not missing_header or len(branch.body) != 1 or not isinstance(branch.body[0], ast.Raise):
                        continue
                    node = branch.body[0]
                    if isinstance(node.exc, ast.Call) and isinstance(node.exc.func, ast.Name) and node.exc.func.id == 'HTTPException':
                        if any(k.arg == 'status_code' and isinstance(k.value, ast.Constant)
                               and k.value.value == 401 for k in node.exc.keywords):
                            dependency_evidence.append({'route_handler': fn.name,
                                'dependency': dep.name, 'rejection_line': node.lineno,
                                'absence_rejected_unconditionally': True})
            a.attributes['entrypoint_env_profile'] = {
                'file': str(path.relative_to(root)), 'keys': sorted(keys),
                'auth_dependency_evidence': dependency_evidence,
                'canonical_guard_symbols_bound': symbols_bound,
                'scope': 'entrypoint literal reads only; libraries/dynamic reads unverified'}
