"""Baseline entry: original ASGI app with error-only auth diagnostics, no guard."""
import importlib
import json
import os
from pathlib import Path
from auth_diagnostic import instrument

module, attribute = os.environ['GUARD_APP_IMPORT'].split(':', 1)
app = getattr(importlib.import_module(module), attribute)
module, attribute = os.environ['GUARD_AUTH_DIAGNOSTIC_IMPORT'].split(':', 1)
owner = importlib.import_module(module)
def record(evidence):
    path = Path(os.environ['RECORD_DIR'])/'auth_rejection.jsonl'
    path.parent.mkdir(exist_ok=True, parents=True)
    with path.open('a', encoding='utf-8') as destination:
        destination.write(json.dumps(evidence)+'\n')
setattr(owner, attribute, instrument(getattr(owner, attribute), record))
