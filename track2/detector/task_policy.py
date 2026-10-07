"""Deployment-owned task permissions; request text and tool output cannot grant them.

Exact principal/task/tool matching and exact parameter values deliberately avoid
prompt classifiers and URL-prefix authorization. Configuring a policy makes it
mandatory for every MCP tool call; missing or unknown task selections deny access.
"""
import copy
import hashlib
import json
from pathlib import Path

class TaskPolicies:
    def __init__(self, document):
        if not isinstance(document, dict) or document.get('version') != 1:
            raise ValueError('Task policy version must be 1')
        tasks = document.get('tasks')
        if not isinstance(tasks, list) or len(tasks) > 256:
            raise ValueError('Task policies must contain a bounded task list')
        self._tasks = {}
        for task in tasks:
            if not isinstance(task, dict) or not isinstance(task.get('id'), str) or not task['id']:
                raise ValueError('Task ID must be a nonempty string')
            if task['id'] in self._tasks:
                raise ValueError('Duplicate task ID')
            principals, permissions = task.get('principals'), task.get('permissions')
            if not isinstance(principals, list) or not principals or not all(isinstance(p, str) and p for p in principals):
                raise ValueError('Task must bind exact principals')
            if not isinstance(permissions, list) or len(permissions) > 128:
                raise ValueError('Task permissions must be a bounded list')
            for grant in permissions:
                if not isinstance(grant, dict) or not all(isinstance(grant.get(k), str) and grant[k] for k in ('server', 'tool')):
                    raise ValueError('Grant must name an exact server and tool')
                arguments = grant.get('arguments')
                if not isinstance(arguments, dict) or len(arguments) > 64:
                    raise ValueError('Grant must explicitly enumerate allowed argument keys')
                for key, values in arguments.items():
                    if not isinstance(key, str) or not isinstance(values, list) or not values or len(values) > 256:
                        raise ValueError('Each argument requires a bounded list of exact allowed values')
            self._tasks[task['id']] = copy.deepcopy(task)
        encoded = json.dumps(document, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        self.digest = hashlib.sha256(encoded).hexdigest()

    @classmethod
    def load(cls, path):
        raw = Path(path).read_bytes()
        if len(raw) > 262144:
            raise ValueError('Task policy file exceeds 256 KiB')
        return cls(json.loads(raw))

    def bind(self, principal, task_id):
        task = self._tasks.get(task_id) if isinstance(task_id, str) else None
        matched = task is not None and principal in task['principals']
        return {'required': True, 'document_sha256': self.digest,
                'task_id': task_id if isinstance(task_id, str) else None,
                'principal': principal, 'matched': matched,
                'permissions': copy.deepcopy(task['permissions']) if matched else []}


def permits(binding, server, tool, arguments):
    if not binding.get('matched') or not isinstance(arguments, dict):
        return False
    for grant in binding.get('permissions', []):
        if grant['server'] != server or grant['tool'] != tool:
            continue
        constraints = grant['arguments']
        # Require exactly these keys: an extra destination/command flag must never
        # escape inspection merely because some other field matched a grant.
        if set(arguments) != set(constraints):
            continue
        if all(any(type(arguments[k]) is type(v) and arguments[k] == v for v in allowed)
               for k, allowed in constraints.items()):
            return True
    return False
