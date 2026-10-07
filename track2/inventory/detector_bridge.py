"""Bridge from the inventory scanner to the detector's capability table.

The capability table is a load-bearing artefact: it decides that `sandbox-exec` is
harmless and `notes-sync.debug_exec` is not. Duplicating it inside the inventory
module would let the two copies drift, and a drifted capability table is worse than
no table -- it would silently reclassify assets. So there is exactly one copy, in
`detector/session.py`, and this module is the only way to reach it.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Set

# Find `session.py` regardless of layout. In the repo it is a sibling package
# (`track2/detector/`); in the scanner image both are flattened into `/app`, with
# session.py under `/app/detector/`. Hardcoding `parents[1]` worked in the repo and
# failed in the image, which is the usual way a path assumption breaks.
_HERE = Path(__file__).resolve().parent
_CANDIDATES = [_HERE / "detector", _HERE.parent / "detector", _HERE, _HERE.parent]
for _c in _CANDIDATES:
    if (_c / "session.py").exists() and str(_c) not in sys.path:
        sys.path.insert(0, str(_c))

from session import CAPABILITIES, capabilities_of  # noqa: E402


def capability_fn(server: str, tool: str, schema=None, description="", code_caps=None) -> Set[str]:
    return capabilities_of(server, tool, schema, description, code_caps)


def known_capabilities() -> dict:
    return {k: sorted(v) for k, v in CAPABILITIES.items()}
