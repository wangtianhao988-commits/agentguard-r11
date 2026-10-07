import base64
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'detector'))
from knowledge_graph import KnowledgeGuard, Graph
from session import ToolCall, register_tool


class KnowledgeGraphTests(unittest.TestCase):
    def setUp(self):
        register_tool('docs', 'read', {}, 'Read document', {'fs_read'})
        register_tool('relay', 'submit', {}, 'Send externally', {'net'})
        self.read = ToolCall('docs', 'read', {'path': '/config'})
        self.secret = 'test-Key-84bx19fnP2Q7'

    def test_encoded_value_in_unusual_parameter_has_inferred_path(self):
        engine = KnowledgeGuard()
        engine.observe('alice', 's1', self.read, {'api_key': self.secret})
        value = base64.b64encode(self.secret.encode()).decode()
        findings = engine.check('alice', 's2', ToolCall('relay', 'submit', {'custom_field': value}))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['transform'], 'base64')
        self.assertNotIn(self.secret, str(findings))
        self.assertEqual(findings[0]['path'][0]['src'], 'source')
        self.assertEqual(findings[0]['path'][-1]['dst'], 'effect')

    def test_unrelated_subject_cannot_inherit_source_without_lineage(self):
        engine = KnowledgeGuard()
        engine.observe('alice', 's1', self.read, {'api_key': self.secret})
        self.assertEqual(engine.check('bob', 's2', ToolCall('relay', 'submit', {'x': self.secret})), [])

    def test_ordinary_report_not_secret_disclosure(self):
        engine = KnowledgeGuard()
        engine.observe('alice', 's1', self.read, {'api_key': self.secret})
        self.assertEqual(engine.check('alice', 's2', ToolCall('relay', 'submit', {'x': 'Keys were rotated this week.'})), [])

    def test_source_and_transform_ablations_remove_specific_evidence(self):
        for missing in ['source', 'transform', 'temporal']:
            engine = KnowledgeGuard({'source','authorization','temporal','transform','memory'}-{missing})
            engine.observe('alice', 's1', self.read, {'api_key': self.secret})
            value = base64.b64encode(self.secret.encode()).decode()
            self.assertEqual(engine.check('alice', 's2', ToolCall('relay', 'submit', {'x': value})), [])

    def test_graph_query_requires_actual_edges(self):
        graph = Graph()
        graph.node('a', 'Call'); graph.node('b', 'Data'); graph.node('c', 'Effect')
        graph.edge('a', 'returns', 'b')
        self.assertIsNone(graph.path('a', 'c', {'returns'}))

    def test_source_saturation_is_visible_and_fails_closed(self):
        engine = KnowledgeGuard(max_sources=1)
        engine.observe('alice', 's1', self.read, {'api_key': self.secret, 'password': 'another-test-value-55'})
        self.assertTrue(engine.saturated)
        self.assertEqual(engine.check('alice', 's1', ToolCall('relay', 'submit', {'x': 'ordinary'}))[0]['rule_id'], 'kg-state-budget')

    def test_shared_resource_actual_read_carries_cross_principal_lineage(self):
        register_tool('memo', 'save', {}, 'Store a document', {'fs_write'})
        register_tool('memo', 'load', {}, 'Read a document', {'fs_read'})
        engine = KnowledgeGuard()
        engine.observe('alice', 'a', self.read, {'api_key': self.secret})
        write = ToolCall('memo', 'save', {'scope':'shared', 'key':'incident', 'text':self.secret})
        engine.observe('alice', 'a', write, {'saved':True})
        read = ToolCall('memo', 'load', {'scope':'shared', 'key':'incident'})
        engine.observe('bob', 'b', read, {'text':self.secret})
        finding = engine.check('bob', 'b', ToolCall('relay', 'submit', {'opaque':self.secret}))[0]
        self.assertIn('read_by', [edge['relation'] for edge in finding['path']])
        self.assertEqual(len(finding['path']), 9)

    def test_address_or_value_mismatch_does_not_prove_memory_lineage(self):
        register_tool('memo', 'save', {}, 'Store a document', {'fs_write'})
        register_tool('memo', 'load', {}, 'Read a document', {'fs_read'})
        for wrong_key, returned in [('different', self.secret), ('incident', 'ordinary content')]:
            engine = KnowledgeGuard()
            engine.observe('alice', 'a', self.read, {'api_key':self.secret})
            engine.observe('alice', 'a', ToolCall('memo','save',{'scope':'shared','key':'incident','text':self.secret}), {'saved':True})
            engine.observe('bob','b',ToolCall('memo','load',{'scope':'shared','key':wrong_key}), {'text':returned})
            self.assertEqual(engine.check('bob','b',ToolCall('relay','submit',{'x':self.secret})), [])

    def test_exact_admin_grant_and_identity_are_required(self):
        from task_policy import TaskPolicies
        policy = TaskPolicies({'version':1,'tasks':[{'id':'export','principals':['alice'],
            'permissions':[{'server':'relay','tool':'submit','arguments':{'x':[self.secret]}}]}]})
        engine = KnowledgeGuard()
        engine.observe('alice','s',self.read,{'api_key':self.secret})
        allowed = ToolCall('relay','submit',{'x':self.secret},trusted_task_policy=policy.bind('alice','export'))
        self.assertEqual(engine.check('alice','s',allowed), [])
        self.assertEqual(engine.check('bob','s',allowed)[0]['rule_id'], 'kg-authorization')
        changed = ToolCall('relay','submit',{'x':self.secret,'extra':'admin'},trusted_task_policy=policy.bind('alice','export'))
        self.assertEqual(engine.check('alice','s',changed)[0]['rule_id'], 'kg-authorization')

    def test_missing_shared_memory_edges_prevent_cross_principal_inference(self):
        register_tool('memo','save',{},'Store a document',{'fs_write'})
        register_tool('memo','load',{},'Read a document',{'fs_read'})
        engine = KnowledgeGuard({'source','authorization','temporal','transform'})
        engine.observe('alice','a',self.read,{'api_key':self.secret})
        engine.observe('alice','a',ToolCall('memo','save',{'scope':'shared','key':'k','text':self.secret}), {'saved':True})
        engine.observe('bob','b',ToolCall('memo','load',{'scope':'shared','key':'k'}), {'text':self.secret})
        self.assertEqual(engine.check('bob','b',ToolCall('relay','submit',{'x':self.secret})), [])

    def test_failed_read_cannot_seed_a_source(self):
        engine = KnowledgeGuard()
        engine.observe('alice','a',self.read,{'api_key':self.secret},ok=False)
        self.assertEqual(engine.check('alice','a',ToolCall('relay','submit',{'x':self.secret})), [])

    def test_traversal_and_invalid_configuration_fail_loudly(self):
        from knowledge_graph import strings
        value = 'leaf'
        for _ in range(34): value = [value]
        with self.assertRaises(ValueError): strings(value)
        with self.assertRaises(ValueError): KnowledgeGuard({'unknown'})
        with self.assertRaises(ValueError): KnowledgeGuard(max_sources=0)

    def test_documentation_metadata_is_not_a_credential(self):
        engine = KnowledgeGuard()
        engine.observe('alice','s',self.read,{'api_key_docs':self.secret,'secretary':self.secret})
        self.assertEqual(engine.check('alice','s',ToolCall('relay','submit',{'x':self.secret})), [])

    def test_large_return_preserved_with_visible_incomplete_provenance(self):
        import os
        from unittest.mock import patch
        import rules
        from session import Session
        with patch.dict(os.environ, {'GUARD_KG':'1'}):
            rules.clear_cross_session_state()
            result = {'content':'x'*65537}
            self.read.result, self.read.ok = result, True
            session = Session('large', identity={'sub':'alice'}, calls=[self.read])
            rules.observe_knowledge_result(session,0)
            self.assertIs(self.read.result, result)
            engine = rules.knowledge_engine()
            self.assertTrue(engine.saturated)
            self.assertEqual(engine.stats['observation_errors'],1)
            rules.observe_knowledge_result(session,0)
            self.assertEqual(engine.stats['observation_errors'],1)
            self.assertEqual(engine.check('alice','large',ToolCall('relay','submit',{'x':'ordinary'}))[0]['rule_id'],'kg-state-budget')
            rules.clear_cross_session_state()


if __name__ == '__main__':
    unittest.main(verbosity=2)
