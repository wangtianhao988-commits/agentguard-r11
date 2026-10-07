import json,math,sys,unittest
from pathlib import Path
import requests
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/'collector'),str(Path(__file__).resolve().parents[1]/'detector')]
from json_codec import loads,response_json
from trusted_plan import digest

class CodecTests(unittest.TestCase):
    def test_large_object_ids_and_boolean_integer_bindings_remain_exact(self):
        original={'id':2**96+7,'negative_id':-2**80-3,'flag':True,'number':1,'decimal':1.0}
        parsed=loads(json.dumps(original).encode());self.assertEqual(digest(parsed),digest(original))
        self.assertIs(type(parsed['id']),int);self.assertIs(type(parsed['flag']),bool);self.assertIs(type(parsed['decimal']),float)
    def test_unicode_legacy_encodings_and_duplicate_key_semantics(self):
        original={'text':'攻击🔐\u0000','id':123};raw=json.dumps(original,ensure_ascii=False)
        for encoded in [raw,raw.encode(),raw.encode('utf-16'),raw.encode('utf-32')]:self.assertEqual(loads(encoded),original)
        self.assertEqual(loads(b'{"id":1,"id":2}'),{'id':2})
    def test_legacy_values_and_malformed_requests_do_not_silently_change(self):
        self.assertTrue(math.isnan(loads('NaN')));self.assertTrue(math.isinf(loads('1e999')))
        self.assertEqual(loads('"\\ud800"'),json.loads('"\\ud800"'))
        for raw in ['{"cmd":','[1,]','not json']:
            with self.assertRaises(ValueError):loads(raw)
    def test_http_response_charset_remains_authoritative(self):
        response=requests.Response();response.encoding='iso-8859-1';response._content=b'{"value":"caf\xe9"}'
        self.assertEqual(response_json(response),{'value':'café'})
        response.encoding='utf-8';response._content=b'{"id":79228162514264337593543950343}'
        self.assertEqual(response_json(response)['id'],2**96+7)
if __name__=='__main__':unittest.main()
