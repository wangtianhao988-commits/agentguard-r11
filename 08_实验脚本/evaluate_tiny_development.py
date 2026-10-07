"""Development-only model comparison. Previously used traces are NOT a holdout."""
import json, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'track2/detector'))
from injection_classifier import InjectionClassifier

def content(value):
    if isinstance(value, str): return value
    if isinstance(value, list): return '\n'.join(v.get('content', v.get('text', '')) for v in value)
    return ''

if __name__ == '__main__':
    model = InjectionClassifier(ROOT / 'track2/models/r11_tiny')
    development = ROOT / '07_修复验证/development_R10'
    traces = []
    start = time.perf_counter()
    for item in json.loads((development / 'selection.json').read_text()):
        trace = json.loads((development / 'raw' / item['path']).read_text(encoding='utf-8'))
        positives = [v for v in trace.get('injections', {}).values() if isinstance(v, str)]
        # Injection labels are used ONLY for scoring, never inside the detector.
        attacked = trace['attack_type'] not in (None, 'none')
        rows = []
        for index, message in enumerate(trace['messages']):
            if message['role'] != 'tool': continue
            text = content(message.get('content'))
            result = model.inspect([text])
            rows.append({'index': index, **(result or {})})
        traces.append({'path': item['path'], 'attacked': attacked, 'historically_successful': attacked and trace.get('security') is True and trace.get('error') is None,
                       'result_denied': any(v.get('block') for v in rows), 'rows': rows})
    def aggregate(rows):
        return {'n': len(rows), 'denied': sum(v['result_denied'] for v in rows)}
    output = ROOT / '07_修复验证/tiny_development'
    output.mkdir(exist_ok=True)
    summary = {'development_only': True, 'wall_s': time.perf_counter() - start, 'stats': model.stats,
               'attacked': aggregate([v for v in traces if v['attacked']]),
               'historically_successful': aggregate([v for v in traces if v['historically_successful']]),
               'benign': aggregate([v for v in traces if not v['attacked']])}
    (output / 'cases.jsonl').write_text(''.join(json.dumps(v) + '\n' for v in traces), encoding='utf-8')
    (output / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print(json.dumps(summary), flush=True)
