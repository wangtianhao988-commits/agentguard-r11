"""Discover literal, deployed create_server registries without invoking handlers.

Only top-level direct registry lists are accepted. Arbitrary Tool() expressions,
dead branches and computed names are not evidence of a deployed tool.
"""
import ast
from pathlib import Path
from scanner import Asset, TOOL

def enrich_registry(graph, root, capabilities):
    for path in sorted((Path(root)/'mcp').rglob('*.py')):
        try:
            tree = ast.parse(path.read_text(encoding='utf-8'))
        except (OSError, SyntaxError, UnicodeError):
            continue
        for statement in tree.body:
            value = getattr(statement, 'value', None)
            if not isinstance(statement, (ast.Assign, ast.AnnAssign)) or not isinstance(value, ast.Call):
                continue
            if not isinstance(value.func, ast.Name) or value.func.id != 'create_server' or len(value.args) < 2:
                continue
            name, tools = value.args[:2]
            if not isinstance(name, ast.Constant) or not isinstance(name.value, str) or not isinstance(tools, (ast.List, ast.Tuple)):
                continue
            server = name.value
            if 'mcp:'+server not in graph.assets:
                continue  # Source artefacts outside the discovered deployment stay unbound.
            for node in tools.elts:
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != 'Tool' or len(node.args) < 4:
                    continue
                tool, _, schema, handler = node.args[:4]
                if not isinstance(tool, ast.Constant) or not isinstance(tool.value, str) or not isinstance(handler, ast.Name):
                    continue
                hidden = next((k.value for k in node.keywords if k.arg == 'hidden'),
                              node.args[4] if len(node.args) > 4 else ast.Constant(False))
                if not isinstance(hidden, ast.Constant) or not isinstance(hidden.value, bool):
                    continue
                aid = 'tool:'+server+'.'+tool.value
                proof = {'file': str(path.relative_to(root)), 'line': node.lineno,
                         'handler': handler.id, 'hidden': hidden.value,
                         'scope': 'literal top-level deployed create_server registry'}
                if aid in graph.assets:
                    previous = graph.assets[aid].attributes.get('source_registration')
                    if previous and previous != proof:
                        graph.assets[aid].attributes['source_registration_ambiguous'] = True
                    graph.assets[aid].attributes['source_registration'] = proof
                    continue
                try:
                    input_schema = ast.literal_eval(schema)
                except (ValueError, TypeError):
                    input_schema = None
                graph.add(Asset(aid, TOOL, server+'.'+tool.value, 'source.registration', {
                    'server': server, 'input_schema': input_schema, 'description': '',
                    'declared_in_tools_list': False, 'source_registration': proof,
                    'code_caps': sorted(capabilities.get(server+'.'+tool.value, set()))}))
                graph.link('mcp:'+server, aid, 'registers_unlisted')
