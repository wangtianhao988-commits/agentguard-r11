"""Exercise both real upstream engines against an inert HTTP server in Docker."""
import asyncio
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

from fastapi import FastAPI, Request, Response
app = FastAPI()

@app.api_route('/echo', methods=['GET', 'POST'])
async def echo(request: Request):
    body = await request.body()
    return {'sha256': hashlib.sha256(body).hexdigest(),
            'query': list(request.query_params.multi_items()),
            'cookie': request.headers.get('cookie'), 'auth': request.headers.get('authorization')}

@app.get('/set-cookie')
async def cookie():
    return Response('ok', headers={'set-cookie': 'session=alice; Path=/'})

@app.get('/redirect')
async def redirect():
    return Response(status_code=307, headers={'location': '/echo'})

@app.get('/gzip')
async def compressed():
    return Response(gzip.compress(b'{"compressed":true}'),
                    headers={'content-encoding': 'gzip'}, media_type='application/json')

@app.get('/slow')
async def slow():
    await asyncio.sleep(2)
    return {'ok': True}

async def exercise(engine):
    os.environ['GUARD_HTTP_TRANSPORT'] = engine
    from upstream import UpstreamClient
    client = UpstreamClient(3)
    base = 'http://127.0.0.1:18081'
    raw = bytes([0, 255, 128, 1]) + b'original-body'
    query = [('k', 'first'), ('k', 'second'), ('unicode', '中文')]
    try:
        response = await client.request('POST', base+'/echo', content=raw, params=query,
                    headers={'Content-Type': 'application/octet-stream', 'Authorization': 'Bearer inert'})
        body = response.json()
        assert body['sha256'] == hashlib.sha256(raw).hexdigest()
        assert body['query'] == [list(p) for p in query]
        assert body['auth'] == 'Bearer inert'
        await client.get(base+'/set-cookie')
        assert (await client.get(base+'/echo')).json()['cookie'] is None
        assert (await client.get(base+'/echo', headers={'Cookie': 'session=bob'})).json()['cookie'] == 'session=bob'
        response = await client.get(base+'/redirect')
        assert response.status_code == 307 and response.headers.get('location') == '/echo'
        assert (await client.get(base+'/gzip')).json() == {'compressed': True}
        started = time.perf_counter()
        try:
            await client.get(base+'/slow', timeout=.03)
        except (TimeoutError, __import__('httpx').TimeoutException):
            pass
        else:
            raise AssertionError('Transport did not enforce timeout')
        assert time.perf_counter()-started < .5
        assert (await client.get(base+'/echo')).status_code == 200
        return {'engine': engine, 'raw_bytes': True, 'duplicate_query': True,
                'authorization': True, 'cookie_isolation': True, 'no_redirect_following': True,
                'gzip_json': True, 'timeout_and_pool_recovery': True}
    finally:
        await client.aclose()

def main():
    env = dict(os.environ, PYTHONPATH='/src/tests:/src/collector')
    process = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'transport_contract:app',
        '--app-dir', '/src/tests', '--host', '127.0.0.1', '--port', '18081', '--log-level', 'warning'], env=env)
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for attempt in range(50):
            try:
                opener.open('http://127.0.0.1:18081/echo', timeout=1).read()
                break
            except Exception:
                time.sleep(.1)
        else:
            raise RuntimeError('Inert test server did not start')
        result = [asyncio.run(exercise(engine)) for engine in ['httpx', 'aiohttp']]
        Path('/evidence/transport_contract.json').write_text(json.dumps(result, indent=2))
        print(json.dumps(result))
    finally:
        process.terminate()
        process.wait(timeout=10)

if __name__ == '__main__':
    main()
