import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'detector'))
from trusted_plan import ControlPlans, PlanDenied, bounded_json
from controlled_executor import ControlledExecutor
from test_trusted_plan import policy

class Boundaries(unittest.TestCase):
    def test_boolean_policy_version_and_invalid_schema_rejected(self):
        document=policy();document['version']=True
        with self.assertRaises(ValueError):ControlPlans(document)
        for spec in [{'type':'unsupported'}, {'type':'string','max_length':True}, {'type':'number','enum':[False]}]:
            document=policy();document['plans'][0]['inputs']['recipient']=spec
            with self.assertRaises(ValueError):ControlPlans(document)

    def test_invalid_labels_rejected_before_transport(self):
        for labels in [[],[''], 'private', [123]]:
            document=policy();document['plans'][0]['steps'][0]['result_labels']=labels
            with self.assertRaises(ValueError):ControlPlans(document)

    def test_recursive_and_oversized_transport_results_stop(self):
        cyclic=[];cyclic.append(cyclic)
        for value in [cyclic, 'x'*131073, float('nan'), {'x':object()}, list(range(5000))]:
            calls=[]
            def transport(server,tool,args):calls.append(tool);return value
            with self.assertRaises(PlanDenied):ControlledExecutor(ControlPlans(policy())).execute('alice','mail',{'recipient':'bob@example.org'},transport)
            self.assertEqual(calls,['read'])

    def test_depth_and_plain_values(self):
        value={}
        for _ in range(40):value={'next':value}
        with self.assertRaises(PlanDenied):bounded_json(value)
        self.assertEqual(bounded_json({'finite':[1,2.0,True,None]}),{'finite':[1,2.0,True,None]})

if __name__=='__main__':unittest.main()
