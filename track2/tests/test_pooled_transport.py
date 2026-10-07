import sys,threading,unittest,json
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from pathlib import Path
import requests
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'collector'))
from pooled_transport import BorrowedPools

class Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def do_GET(self):
        body=json.dumps({'authorization':self.headers.get('Authorization'),'cookie':self.headers.get('Cookie'),'port':self.client_address[1]}).encode()
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.send_header('Set-Cookie','test=accepted; Path=/');self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass

class PoolTests(unittest.TestCase):
    def test_connection_reuse_keeps_session_identity_and_cookie_semantics(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        pools=BorrowedPools(requests.Session.send)
        try:
            url=f'http://127.0.0.1:{server.server_port}/'
            with requests.Session() as alice,requests.Session() as bob:
                alice.trust_env=bob.trust_env=False
                alice.headers['Authorization']='Bearer alice';bob.headers['Authorization']='Bearer bob'
                original=alice.adapters.copy()
                first=pools.send(alice,alice.prepare_request(requests.Request('GET',url)),timeout=3).json()
                second=pools.send(bob,bob.prepare_request(requests.Request('GET',url)),timeout=3).json()
                third=pools.send(alice,alice.prepare_request(requests.Request('GET',url)),timeout=3).json()
                self.assertEqual(first['port'],second['port']);self.assertEqual(second['port'],third['port'])
                self.assertEqual(second['authorization'],'Bearer bob');self.assertIsNone(second['cookie'])
                self.assertEqual(third['cookie'],'test=accepted');self.assertEqual(third['authorization'],'Bearer alice')
                self.assertEqual(alice.adapters,original)
        finally:pools.close();server.shutdown();server.server_close();thread.join()
    def test_custom_adapter_remains_authoritative(self):
        class Adapter(requests.adapters.HTTPAdapter):pass
        session=requests.Session();adapter=Adapter();session.mount('http://',adapter)
        called=[]
        pools=BorrowedPools(lambda actual,request,**kwargs:called.append(actual.get_adapter(request.url)))
        pools.send(session,requests.Request('GET','http://example.invalid').prepare())
        self.assertEqual(called,[adapter]);self.assertFalse(pools.adapters);session.close()

if __name__=='__main__':unittest.main()
