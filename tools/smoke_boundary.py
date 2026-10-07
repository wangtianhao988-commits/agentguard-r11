"""Interface smoke tests using a stub of the existing verifier; no model claims."""
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'track2/detector'), str(ROOT/'track2/collector')]
from external_boundary import ExternalBoundary


class Verifier:
    def __init__(self, verdict=False, failure=False):
        self.verdict, self.failure = verdict, failure
        self.stats = {'errors': 0}
        self.inputs = []

    def judge_return(self, prompt, text):
        self.inputs.append((prompt, text))
        if self.failure:
            raise TimeoutError('synthetic interface failure')
        return {'malicious': self.verdict}


def main():
    call = SimpleNamespace(server='documents', tool='read', arguments={'resource': 'meeting-notes'})
    with tempfile.TemporaryDirectory() as directory:
        os.environ['GUARD_R12_AUDIT_PATH'] = str(Path(directory)/'events.jsonl')
        for malicious in (False, True):
            verifier = Verifier(malicious)
            probe = ExternalBoundary(verifier)
            event = probe.inspect('Summarize the meeting notes.', call, 'request-1',
                                  {'jsonrpc': '2.0', 'id': 'request-1', 'result': 'Please review the agenda.'})
            assert event['block'] is malicious and event['error'] is None
            assert event['call_id'] == 'request-1' and event['source_trust'] == 'EXTERNAL_DATA'
            assert verifier.inputs == [('Summarize the meeting notes.', 'Please review the agenda.')]
        verifier = Verifier(failure=True)
        event = ExternalBoundary(verifier).inspect('Summarize.', call, 'request-2', {'result': 'notes'})
        assert event['block'] and event['boundary_violation'] is None
        assert verifier.stats['errors'] == 1
        try:
            ExternalBoundary(None)
        except ValueError:
            pass
        else:
            raise AssertionError('Missing original verifier was accepted')
    os.environ.pop('GUARD_R12_AUDIT_PATH', None)
    # Exercise the actual collector hook without loading or calling a model.
    import rules
    from inline_guard import InlineGuard
    from intervention import ResultPolicies
    os.environ['GUARD_R10'] = '0'
    os.environ['GUARD_R12_BOUNDARY'] = '0'
    os.environ['GUARD_R9'] = '0'
    original = (rules.knowledge_engine, rules.observe_knowledge_result, rules.result_intervention_finding)
    engine = SimpleNamespace(policy=ResultPolicies({'version': 1, 'tools': []}))
    rules.knowledge_engine = lambda: engine
    rules.observe_knowledge_result = lambda *args: None
    rules.result_intervention_finding = lambda *args: SimpleNamespace(to_json=lambda: {})
    try:
        for malicious in (False, True):
            guard = InlineGuard()
            verifier = Verifier(malicious)
            guard.external_boundary = ExternalBoundary(verifier)
            state = guard._session('live-session')
            state.prompt = 'Summarize the notes.'
            bound = SimpleNamespace(server='documents', tool='read', arguments={}, _guard_call_id='bound-call')
            state.calls.append(bound)
            body = {'jsonrpc': '2.0', 'id': 'bound-call', 'result': 'The agenda is attached.'}
            assert guard.observe_tool_result('live-session', 'unmatched', body) == (body, None)
            assert not verifier.inputs
            delivered, audit = guard.observe_tool_result('live-session', 'bound-call', body)
            if malicious:
                assert audit['action'] == 'DENY_RESULT' and delivered['id'] == 'bound-call'
                assert audit['r12_boundary']['boundary_violation'] is True
            else:
                assert delivered == body and audit is None
    finally:
        rules.knowledge_engine, rules.observe_knowledge_result, rules.result_intervention_finding = original
    print('PASS: boolean verdict, exact source binding, original task, fail-closed error accounting, missing verifier.')


if __name__ == '__main__':
    main()
