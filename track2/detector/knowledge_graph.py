"""Bounded security knowledge and path inference from observed facts.

Returned credential-shaped values are evidence of *suspected* sensitive content,
not proof of valid credentials. No instruction or tool response can grant access.
Exact data matches establish observed lineage, not LLM causal attribution.
"""
import base64
from collections import OrderedDict, deque
import hashlib
import json
import re
from urllib.parse import quote, unquote, urlsplit, parse_qsl

LABEL = re.compile(r'(?:^|[_-])(?:password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key|credential)$', re.I)
ASSIGNMENT = re.compile(r'(?im)^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*[:=]\s*[\"\']?([^\s\"\']{12,1024})')
TOKENS = re.compile(r'[A-Za-z0-9_%+/.:=-]{12,2048}')


def strings(value, limit=65536):
    """Bound all leaf traversal, including adversarial nested JSON."""
    stack, result, nodes, size = [(value, 0)], [], 0, 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > 32 or nodes > 4096:
            raise ValueError('KG JSON traversal budget exceeded')
        if isinstance(item, str):
            size += len(item)
            if size > limit:
                raise ValueError('KG text budget exceeded')
            result.append(item)
        elif isinstance(item, dict):
            stack.extend((v, depth+1) for v in item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend((v, depth+1) for v in item)
    return result


def credential_values(value):
    texts = strings(value)
    found = set()
    stack = [value]
    # MCP often returns JSON as a text block. Decode only a bounded number of
    # structured views; never execute content or accept embedded authority.
    for text in texts[:16]:
        if text.lstrip().startswith(('{', '[')):
            try:
                parsed = json.loads(text)
                strings(parsed)
                stack.append(parsed)
            except (ValueError, RecursionError):
                pass
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, val in item.items():
                if LABEL.search(str(key)) and isinstance(val, str) and 12 <= len(val) <= 1024:
                    found.add(val)
                stack.append(val)
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
    for text in texts:
        for match in ASSIGNMENT.finditer(text):
            if LABEL.search(match[1]):
                found.add(match[2])
    return found


def candidates(value):
    for text in strings(value):
        yield text
        yield from TOKENS.findall(text)
        for line in text.splitlines():
            if '=' in line:
                yield line.split('=', 1)[1].strip(' \"\'')
        if '://' in text:
            try:
                yield from (v for _, v in parse_qsl(urlsplit(text).query))
            except ValueError:
                pass


class Graph:
    def __init__(self):
        self.nodes, self.edges = {}, []

    def node(self, identifier, kind, **facts):
        self.nodes[identifier] = {'id': identifier, 'kind': kind, **facts}
        return identifier

    def edge(self, src, relation, dst):
        self.edges.append({'src': src, 'relation': relation, 'dst': dst})

    def path(self, start, goal, relations, max_depth=10):
        pending, seen = deque([(start, [])]), {start}
        while pending:
            node, trail = pending.popleft()
            if node == goal:
                return trail
            if len(trail) >= max_depth:
                continue
            for edge in self.edges:
                if edge['src'] == node and edge['relation'] in relations and edge['dst'] not in seen:
                    seen.add(edge['dst'])
                    pending.append((edge['dst'], trail+[edge]))
        return None

    def json(self):
        return {'nodes': list(self.nodes.values()), 'edges': self.edges}


class KnowledgeGuard:
    def __init__(self, components=None, max_sources=128):
        supported = {'source', 'authorization', 'temporal', 'transform', 'memory'}
        self.components = supported if components is None else set(components)
        if not self.components <= supported or type(max_sources) is not int or not 1 <= max_sources <= 1024:
            raise ValueError('Invalid KG components or source budget')
        self.max_sources = max_sources
        self.sources, self.forms, self.exposures, self.artifacts = OrderedDict(), {}, {}, OrderedDict()
        self.lineage = {}
        self.sequence, self.last_session, self.saturated = 0, None, False
        self.stats = {'checked': 0, 'findings': 0, 'source_values': 0, 'observation_errors': 0}

    def _tick(self, session):
        if 'temporal' not in self.components and self.last_session != session:
            self.sources.clear(); self.forms.clear(); self.exposures.clear(); self.artifacts.clear()
            self.lineage.clear()
            self.saturated = False
        self.last_session = session
        self.sequence += 1
        return self.sequence

    def observe(self, principal, session, call, result, ok=True):
        if not ok or 'source' not in self.components or not principal:
            return
        seq = self._tick(session)
        resource = self._resource(call)
        matches = self._matches(call.arguments, principal)
        if 'memory' in self.components and resource and 'fs_write' in call.caps and matches:
            if resource not in self.artifacts and len(self.artifacts) >= self.max_sources:
                self.saturated = True
                return
            self.artifacts[resource] = {'keys': {key for key, _ in matches},
                'writer': principal, 'session': session, 'sequence': seq}
        # Only observed reads can introduce data sources; tool text cannot invent
        # a permission or claim that some unobserved read happened.
        if not (set(call.caps) & {'fs_read', 'db_read', 'read_only'}):
            return
        if 'memory' in self.components and resource in self.artifacts:
            artifact = self.artifacts[resource]
            # A matching address alone is insufficient. The read must actually
            # return a representation of the content previously stored there.
            for text in candidates(result):
                for key, _ in self.forms.get(text, []):
                    if key in artifact['keys']:
                        self._expose(principal, key)
                        self.lineage[(principal, key)] = {'resource': resource,
                            'write': dict(artifact, keys=None), 'read_session': session, 'read_sequence': seq}
        for value in credential_values(result):
            fingerprint = hashlib.sha256(value.encode()).hexdigest()
            key = (principal, fingerprint)
            if key not in self.sources:
                if len(self.sources) >= self.max_sources:
                    self.saturated = True
                    continue
                self.sources[key] = {'principal': principal, 'session': session,
                    'server': call.server, 'tool': call.tool, 'sequence': seq,
                    'fingerprint': fingerprint}
                self.stats['source_values'] += 1
                forms = {value: 'identity'}
                if 'transform' in self.components:
                    for form, transform in [(base64.b64encode(value.encode()).decode(), 'base64'),
                        (value.encode().hex(), 'hex'), (quote(value, safe=''), 'urlencoding')]:
                        forms.setdefault(form, transform)
                for form, transform in forms.items():
                    self.forms.setdefault(form, []).append((key, transform))
            self._expose(principal, key)

    def _expose(self, principal, key):
        if principal not in self.exposures and len(self.exposures) >= self.max_sources*2:
            self.saturated = True
            return
        self.exposures.setdefault(principal, set()).add(key)

    def _resource(self, call):
        if call.arguments.get('scope') != 'shared':
            return None
        for key in ['key', 'path', 'memory_key', 'document_id', 'id']:
            value = call.arguments.get(key)
            if isinstance(value, (str, int)) and not isinstance(value, bool):
                encoded = json.dumps([call.server, key, value], ensure_ascii=False)
                if len(encoded) > 2048:
                    raise ValueError('KG resource identity budget exceeded')
                return hashlib.sha256(encoded.encode()).hexdigest()
        return None

    def _matches(self, arguments, principal):
        if not self.forms:
            return []
        exposed = self.exposures.get(principal, set())
        return [(key, transform) for text in candidates(arguments)
                for key, transform in self.forms.get(text, []) if key in exposed]

    def _authorization(self, principal, call):
        binding = call.trusted_task_policy
        if 'authorization' not in self.components or not binding or not binding.get('required'):
            return None, None
        from task_policy import permits
        graph = Graph()
        graph.node('principal', 'Principal', name=principal)
        graph.node('task', 'Task', task_id=binding.get('task_id'), policy_sha256=binding.get('document_sha256'))
        graph.node('tool', 'Tool', server=call.server, name=call.tool)
        if binding.get('matched') and principal == binding.get('principal'):
            graph.edge('principal', 'authorized_for', 'task')
            for index, grant in enumerate(binding.get('permissions', [])):
                if permits(dict(binding, permissions=[grant]), call.server, call.tool, call.arguments):
                    node = graph.node('grant'+str(index), 'Grant', source='deployment-policy')
                    graph.edge('task', 'has_grant', node)
                    graph.edge(node, 'permits', 'tool')
        path = graph.path('principal', 'tool', {'authorized_for', 'has_grant', 'permits'})
        return path, graph

    def check(self, principal, session, call):
        seq = self._tick(session)
        self.stats['checked'] += 1
        permission, auth_graph = self._authorization(principal, call)
        if auth_graph is not None and permission is None:
            return [{'rule_id': 'kg-authorization', 'summary': 'no exact deployment-owned authorization path',
                     'graph': auth_graph.json(), 'path': [], 'missing_relation': 'principal-task-grant-tool'}]
        if not (set(call.caps) & {'net', 'exec'}) or not principal:
            return []
        if self.saturated:
            return [{'rule_id': 'kg-state-budget', 'summary': 'source ledger saturated; egress cannot be judged', 'graph': {'nodes': [], 'edges': []}}]
        # An exact administrator grant may permit this graph's data flow. It does
        # not remove any independent R6 rule's finding in combined enforcement.
        if permission:
            return []
        for key, transform in self._matches(call.arguments, principal):
                source = self.sources[key]
                if source['sequence'] >= seq:
                    continue
                graph = Graph()
                origin = graph.node('source', 'Call', **source)
                data = graph.node('data', 'Data', fingerprint=source['fingerprint'], classification='credential-shaped-return')
                representation = graph.node('representation', 'Representation', transform=transform)
                sink = graph.node('sink', 'Call', principal=principal, session=session, sequence=seq)
                tool = graph.node('tool', 'Tool', server=call.server, name=call.tool)
                effect = graph.node('effect', 'Capability', name='egress')
                graph.edge(origin, 'returns', data)
                previous = data
                lineage = self.lineage.get((principal, key))
                if lineage:
                    if not (source['sequence'] < lineage['write']['sequence'] < lineage['read_sequence'] < seq):
                        continue
                    writer = graph.node('writer', 'Call', session=lineage['write']['session'], sequence=lineage['write']['sequence'])
                    artifact = graph.node('artifact', 'Resource', resource_fingerprint=lineage['resource'], scope='shared')
                    reader = graph.node('reader', 'Call', session=lineage['read_session'], sequence=lineage['read_sequence'])
                    previous = graph.node('derived', 'Data', fingerprint=source['fingerprint'])
                    graph.edge(data, 'written_by', writer)
                    graph.edge(writer, 'writes', artifact)
                    graph.edge(artifact, 'read_by', reader)
                    graph.edge(reader, 'returns', previous)
                graph.edge(previous, 'encoded_as', representation)
                graph.edge(representation, 'used_as_argument', sink)
                graph.edge(sink, 'invokes', tool)
                graph.edge(tool, 'has_capability', effect)
                path = graph.path(origin, effect, {'returns', 'encoded_as', 'used_as_argument', 'invokes', 'has_capability',
                    'written_by', 'writes', 'read_by'})
                if path:
                    self.stats['findings'] += 1
                    return [{'rule_id': 'kg-sensitive-flow', 'summary': 'observed credential-shaped return reaches egress',
                             'graph': graph.json(), 'path': path, 'transform': transform}]
        return []
