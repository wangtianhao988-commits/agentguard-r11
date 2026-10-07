"""Benign-heavy local replay for profiling; not a competition score."""
import copy
import json
import os
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
RANGE = ROOT / '_scratch/competition/agentrange'
sys.path[:0] = [str(RANGE/'scenario-runner'), str(RANGE/'corpus-generator'), str(RANGE/'attack')]
for name in list(os.environ):
    if name.lower() in {'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'}:
        os.environ.pop(name)
os.environ.update(OPSPILOT_BASE='http://127.0.0.1:8100',
                  LANGFLOW_BASE='http://127.0.0.1:8101/langflow', LLM_STUB_BASE='http://127.0.0.1:8000')
import runner
from generate import generate, public_record, trajectory_map

events = generate()
selected = copy.deepcopy([e for e in events if not e.malicious][:1600])
prefix = 'profile-' + uuid.uuid4().hex[:8] + '-'
for event in selected:
    event.instance_id = prefix + event.instance_id
runner.inject_trajectories(trajectory_map(selected))
try:
    runner.replay_events([public_record(e) for e in selected])
finally:
    runner.clear_trajectories()
print(json.dumps({'events': len(selected), 'prefix': prefix, 'scope': 'profiling workload only'}))
