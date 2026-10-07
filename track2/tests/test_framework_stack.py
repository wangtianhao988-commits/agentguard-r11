"""A pre-upstream refusal must not attach an unrelated Agent worker stack."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

TRACK2 = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(TRACK2/'collector'), str(TRACK2/'detector')]


class FrameworkStackTests(unittest.TestCase):
    def test_block_has_live_gateway_stack_and_never_queries_agent_sidecar(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {'RECORD_DIR': directory}):
                import gateway
                from starlette.requests import Request
                from inline_guard import Decision
                raw = json.dumps({'code': 'inert synthetic test'}).encode()
                async def receive():
                    return {'type': 'http.request', 'body': raw, 'more_body': False}
                request = Request({'type': 'http', 'method': 'POST',
                    'path': '/langflow/api/v1/validate/code', 'query_string': b'',
                    'headers': [(b'content-type', b'application/json')]}, receive)
                records = []
                async def no_sidecar(*args, **kwargs):
                    raise AssertionError('Unrelated Agent stack queried')
                async def no_upstream(*args, **kwargs):
                    raise AssertionError('Blocked request forwarded')
                with patch.object(gateway, '_record', lambda stream, row: records.append((stream, row))), \
                     patch.object(gateway.GUARD, 'check_framework_call', return_value=Decision('BLOCK', 'test', reason='synthetic')), \
                     patch.object(gateway, '_stack_for_decision', no_sidecar), \
                     patch.object(gateway, '_forward', no_upstream), \
                     patch.object(gateway, 'CAPTURE_ON', 'finding'):
                    response = asyncio.run(gateway.obs_e_langflow('api/v1/validate/code', request))
                self.assertEqual(response.status_code, 200)
                stack = next(row for stream, row in records if stream == 'code_stack')
                self.assertEqual(stack['capture_target'], 'guard-gateway')
                self.assertEqual(stack['stage'], 'pre-upstream')
                self.assertFalse(stack['upstream_forwarded'])
                self.assertIn('obs_e_langflow', [f['fn'] for f in stack['threads'][0]['frames']])
                self.assertNotIn('call_mcp', [f['fn'] for f in stack['threads'][0]['frames']])
                gateway.STORE.close()


if __name__ == '__main__':
    # Host evaluation need not install an ASGI server. Use the already-built
    # gateway's pinned dependencies while mounting the exact current test source.
    if importlib.util.find_spec('fastapi') is None:
        raise SystemExit(subprocess.run(['docker', 'run', '--rm', '--network', 'none',
            '--mount', 'type=bind,source='+str(TRACK2)+',target=/src,readonly',
            'agentrange-guard-gateway-r8', 'python', '/src/tests/test_framework_stack.py']).returncode)
    unittest.main(verbosity=2)
