"""Tampering with delivered data, optimum or graph proof must fail replay."""
from pathlib import Path
import json,shutil,sys,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'track2/eval'))
from r8_audit import validate
class Tests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.out=Path(self.directory.name)
        source=ROOT/'07_修复验证/R8_real_adapter_qualified/R8'
        for name in ['result_policy.json','C_raw_response.jsonl','C_response.jsonl','result_intervention.jsonl','guard_decision.jsonl']:
            shutil.copyfile(source/name,self.out/name)
    def tearDown(self):self.directory.cleanup()
    def edit(self,name,mutate):
        p=self.out/(name+'.jsonl');records=[json.loads(x) for x in p.read_text(encoding='utf-8').splitlines()]
        mutate(records);p.write_text('\n'.join(json.dumps(x) for x in records)+'\n',encoding='utf-8')
    def test_actual_adapter_audit_passes(self):
        result=validate(self.out)
        self.assertEqual(result['result_projections'],1);self.assertEqual(result['graph_witnesses_verified'],2)
    def test_delivered_data_tampering_is_rejected(self):
        rid=json.loads((self.out/'C_raw_response.jsonl').read_text(encoding='utf-8').splitlines()[0])['rid']
        def mutate(rows):
            next(r for r in rows if r['rid']==rid)['body']['result']['status']='tampered'
        self.edit('C_response',mutate)
        with self.assertRaises(AssertionError):validate(self.out)
    def test_fabricated_minimum_cost_is_rejected(self):
        self.edit('result_intervention',lambda rows:rows[0]['plan'].update(cost=0))
        with self.assertRaises(AssertionError):validate(self.out)
    def test_fabricated_graph_path_is_rejected(self):
        def mutate(rows):
            f=next(f for r in rows for f in r.get('findings',[]) if f.get('evidence',{}).get('path'))
            f['evidence']['path'][0]['dst']='invented-node'
        self.edit('guard_decision',mutate)
        with self.assertRaises(AssertionError):validate(self.out)
if __name__=='__main__':unittest.main(verbosity=2)
