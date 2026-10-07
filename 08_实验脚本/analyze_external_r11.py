"""Read-only failure inventory. Does not rerun, relabel or discard hard cases."""
import collections,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
base=ROOT/'07_修复验证/external_r11_gemini'
source=base/'results/R11_frozen/cases.jsonl'
rows=[json.loads(line) for line in source.read_text(encoding='utf8').splitlines()]
misses=[r for r in rows if r['attacked'] and r['first_injection'] is not None and not r['validated_interception']]
normal=[r for r in rows if not r['attacked'] and r['refused']]
report={'source':'results/R11_frozen/cases.jsonl',
        'purpose':'Development diagnosis after frozen evaluation, never a new independent result',
        'exposed_misses':len(misses),'exposed_misses_by_suite':dict(collections.Counter(r['suite'] for r in misses)),
        'exposed_miss_paths':[r['path'] for r in misses],
        'normal_refusals':[],
        'limitations':['A missed injection is not necessarily a successful attack: the archived model may resist it.',
                       'A normal-labelled archive may contain an incorrect model action. Original labels and counts remain unchanged.']}
for row in normal:
    trace=json.loads((base/'raw'/row['path']).read_text(encoding='utf8'))
    index=row['first_refusal']['message_index']
    report['normal_refusals'].append({'path':row['path'],
       'task':next(m['content'] for m in trace['messages'] if m['role']=='user'),
       'actual_call':trace['messages'][index].get('tool_calls'),
       'decision':row['first_refusal'],'verifier_errors':row['verifier_errors']})
target=base/'development_failure_inventory.json'
target.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8')
print('Exposed misses:',report['exposed_misses_by_suite'])
print('Normal refusals preserved:',len(normal),'->',target)
