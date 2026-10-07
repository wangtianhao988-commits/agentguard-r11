"""Network-isolated real HTTP auth readiness against the original official app."""
import json
import sys
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch
import httpx
from fastapi.testclient import TestClient

sys.path[:0] = ['/app', '/code/collector', '/driver']
import api.app as target
from token_readiness import wait_for_token

rows = []
class Clock(datetime):
    current_s = 99.993
    @classmethod
    def now(cls, tz=None):
        return datetime.fromtimestamp(cls.current_s, tz)
with TestClient(target.app) as client, patch('auth.jwt_auth.time.time', return_value=100), patch('jwt.api_jwt.datetime', Clock):
    token = client.post('/login', json={'username': 'lwang'}).json()['access_token']
    class Adapter:
        def get(self, url, **kwargs):
            # Exact 7ms failure followed by a later verification time. Only /me
            # is issued: no Agent execution or outbound tools are needed.
            assert url.endswith('/me')
            Clock.current_s = 99.993 if not rows else 100.001
            response = client.get('/me', **kwargs)
            rows.append(response.status_code)
            return response
    ready = wait_for_token(Adapter(), 'http://fixture', 'lwang', token)
    assert rows == [401, 200]
    Clock.current_s = 100.001
    bad = client.get('/me', headers={'Authorization': 'Bearer invalid-signature'})
    assert bad.status_code == 401
    expired = target.issue_token(target.USERS['lwang'], target.SECRET, ttl=1, now=90)
    assert client.get('/me', headers={'Authorization': 'Bearer '+expired}).status_code == 401
    class Rejected:
        def get(self, url, **kwargs):
            return client.get('/me', **kwargs)
    try:
        wait_for_token(Rejected(), 'http://fixture', 'lwang', 'invalid-signature', budget_s=.04)
        raise AssertionError('Invalid token became ready')
    except (httpx.HTTPStatusError, RuntimeError):
        pass
result = {'real_http_status_sequence': rows, 'injected_future_iat_ms': 7,
          'invalid_token': 401, 'expired_token': 401,
          'invalid_token_readiness': 'rejected', 'business_calls_retried': 0,
          'outbound_tool_calls': 0, 'scope': 'original app; controlled clock; network none; not attribution of historical opaque 401'}
destination = Path('/evidence/auth_readiness_http.json')
destination.parent.mkdir(exist_ok=True, parents=True)
destination.write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps(result))
