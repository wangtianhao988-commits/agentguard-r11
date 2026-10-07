from pathlib import Path
import sys,tempfile,unittest,json
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'detector'))
from security_graph import SecurityGraph
from session import ToolCall,register_tool

class Tests(unittest.TestCase):
    def setUp(self):
        register_tool('docs','read',{},'Read a report',{'fs_read'})
        register_tool('relay','submit',{},'Transmit via HTTP',{'net'})
        self.read=ToolCall('docs','read',{})
        self.secret='fixture-s8-secret-731BbQ'
    def test_hash_index_preserves_egress_detection(self):
        engine=SecurityGraph()
        engine.observe('alice','s',self.read,{'api_key':self.secret})
        f=engine.check('alice','s',ToolCall('relay','submit',{'opaque':self.secret}))
        self.assertEqual(f[0]['rule_id'],'kg-sensitive-flow')
        self.assertNotIn(self.secret,str(engine.forms))
        self.assertEqual(f[0]['intervention']['selected'],['deny-current-call'])
    def test_static_inventory_and_real_call_form_joint_witness(self):
        inventory={'asset_graph':{'assets':[{'kind':'tool','name':'docs.read','attributes':{}}]}}
        f=SecurityGraph(inventory=inventory).check('alice','s',ToolCall('docs','unknown',{}))
        self.assertEqual(f[0]['rule_id'],'r8-joint-asset')
        self.assertEqual(len(f[0]['path']),2)
        self.assertFalse(SecurityGraph(inventory=inventory).check('alice','s',self.read))
    def test_restart_recovers_and_namespace_change_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'state.db'
            e=SecurityGraph(state_path=path)
            e.observe('alice','s',self.read,{'api_key':self.secret});e.close()
            e=SecurityGraph(state_path=path)
            self.assertTrue(e.restored)
            self.assertTrue(e.check('alice','next',ToolCall('relay','submit',{'opaque':self.secret})))
            self.assertNotIn(self.secret,path.read_bytes().decode('latin1'))
            e.close()
            with self.assertRaises(ValueError): SecurityGraph(state_path=path,inventory={'asset_graph':{'assets':[]}})
    def test_expiry_is_not_silent_permission(self):
        clock=[10]
        e=SecurityGraph(clock=lambda:clock[0],lease_seconds=3)
        e.observe('alice','s',self.read,{'api_key':self.secret})
        clock[0]=14
        self.assertEqual(e.check('alice','s',ToolCall('relay','submit',{'opaque':self.secret}))[0]['rule_id'],'kg-state-budget')

    def test_two_shared_hops_survive_restart_and_include_every_actor(self):
        register_tool('memo','save',{},'Store a document',{'fs_write'})
        register_tool('memo','read',{},'Read a document',{'fs_read'})
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'state.db'
            e=SecurityGraph(state_path=path)
            e.observe('alice','a',self.read,{'api_key':self.secret})
            for writer,reader,address in [('alice','bob','one'),('bob','carol','two')]:
                e.observe(writer,writer,ToolCall('memo','save',{'scope':'shared','key':address,'opaque':self.secret}),{'saved':True})
                e.observe(reader,reader,ToolCall('memo','read',{'scope':'shared','key':address}),{'text':self.secret})
            e.close();e=SecurityGraph(state_path=path)
            finding=e.check('carol','next',ToolCall('relay','submit',{'opaque':self.secret}))[0]
            self.assertEqual(finding['shared_resource_hops'],2)
            self.assertEqual(len(finding['path']),13)
            actors={n.get('principal') for n in finding['graph']['nodes']}
            self.assertTrue({'alice','bob','carol'}<=actors)
            e.close()

    def test_wrong_resource_cannot_create_propagation(self):
        register_tool('memo','save',{},'Store a document',{'fs_write'})
        register_tool('memo','read',{},'Read a document',{'fs_read'})
        e=SecurityGraph()
        e.observe('alice','a',self.read,{'api_key':self.secret})
        e.observe('alice','a',ToolCall('memo','save',{'scope':'shared','key':'one','opaque':self.secret}),{'saved':True})
        e.observe('bob','b',ToolCall('memo','read',{'scope':'shared','key':'two'}),{'text':self.secret})
        self.assertFalse(e.check('bob','b',ToolCall('relay','submit',{'opaque':self.secret})))

    def test_saturation_survives_restart_even_without_new_source(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'state.db'
            e=SecurityGraph(state_path=path,max_sources=1)
            e.observe('alice','s',self.read,{'api_key':self.secret})
            e.observe('alice','s',self.read,{'api_key':'fixture-second-credential-912'})
            self.assertTrue(e.saturated);e.close()
            e=SecurityGraph(state_path=path,max_sources=1)
            self.assertTrue(e.saturated)
            self.assertEqual(e.check('alice','s',ToolCall('relay','submit',{'opaque':'fixture-second-credential-912'}))[0]['rule_id'],'kg-state-budget')
            e.close()

    def test_four_hop_bound_has_full_path_and_fifth_is_explicit_uncertainty(self):
        register_tool('memo','save',{},'Store a document',{'fs_write'})
        register_tool('memo','read',{},'Read a document',{'fs_read'})
        e=SecurityGraph();e.observe('a','s',self.read,{'api_key':self.secret})
        for i in range(4):
            writer,reader=chr(97+i),chr(98+i)
            e.observe(writer,writer,ToolCall('memo','save',{'scope':'shared','key':str(i),'opaque':self.secret}),{'saved':True})
            e.observe(reader,reader,ToolCall('memo','read',{'scope':'shared','key':str(i)}),{'text':self.secret})
        f=e.check('e','s',ToolCall('relay','submit',{'opaque':self.secret}))[0]
        self.assertEqual(f['shared_resource_hops'],4);self.assertEqual(len(f['path']),21)
        e.observe('e','s',ToolCall('memo','save',{'scope':'shared','key':'fifth','opaque':self.secret}),{'saved':True})
        self.assertTrue(e.saturated)

    def test_traversal_uncertainty_remains_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'state.db';e=SecurityGraph(state_path=path)
            with self.assertRaises(ValueError):e.observe('alice','s',self.read,{'text':'x'*65537})
            e.close();e=SecurityGraph(state_path=path)
            self.assertTrue(e.saturated);e.close()

if __name__=='__main__': unittest.main(verbosity=2)
