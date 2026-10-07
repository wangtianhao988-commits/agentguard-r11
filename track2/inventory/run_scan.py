#!/usr/bin/env python
"""Run the inventory scan and emit the asset graph plus risk findings.

Deployment shape
----------------
The scanner runs as a **container on the target's network** with the container
runtime socket mounted. That is not a convenience -- the MCP servers publish no
ports (`docker-compose.yml` gives the 8 `mcp-*` services no `ports:` key), so the
only way to speak MCP to them is from inside `opspilot-net`. It is also how a real
deployment-side scanner is packaged.

    python -m inventory.run_scan --out /evidence/inventory.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from risks import assess  # noqa: E402
from scanner import scan  # noqa: E402

#: MCP endpoints, derived the same way the agent derives them: the compose service
#: names on the shared network plus the conventional path. A real scanner would take
#: these from its scope configuration; the point is that they are *addresses*, not
#: answers -- everything about the tools is still probed over the wire.
DEFAULT_MCP = {
    "customer-db": "http://mcp-customer-db:8000/mcp",
    "shell-runner": "http://mcp-shell-runner:8000/mcp",
    "notes-sync": "http://mcp-notes-sync:8000/mcp",
    "threat-intel": "http://mcp-threat-intel:8000/mcp",
    "gitlab": "http://mcp-gitlab:8000/mcp",
    "monitoring": "http://mcp-monitoring:8000/mcp",
    "knowledge": "http://mcp-knowledge:8000/mcp",
    "sandbox-exec": "http://mcp-sandbox-exec:8000/mcp",
}


def read_file_factory(root: Path):
    """Read a file referenced by a skill record.

    Skill records carry an absolute path as seen by the SCANNER. Inside the scanner
    container the range source is mounted at `--range-root`, so paths are rebased
    onto that mount. Doing it here rather than at discovery keeps the record honest
    about what was discovered where.
    """
    def read(path: str) -> Optional[str]:
        p = Path(path)
        if p.exists():
            try:
                return p.read_text(encoding="utf-8")
            except Exception:  # noqa: BLE001
                return None
        try:
            rel = p.relative_to("/")
        except ValueError:
            rel = Path(path.lstrip("/"))
        cand = root / rel
        if cand.exists():
            try:
                return cand.read_text(encoding="utf-8")
            except Exception:  # noqa: BLE001
                return None
        return None
    return read


def collect_sources(root: Path, subdirs: tuple = ("mcp", "skills", "opspilot-app", "langflow")) -> List[Dict[str, Any]]:
    """Enumerate the deployable artefacts a supply-chain scanner would read.

    Reading the code you are asked to deploy is the definition of this category --
    a protocol probe can never see a startup hook, because it runs before any call.
    Subdirectories are named because that is where the deployment's own components
    live; the file selection inside them is by extension, not by name.
    """
    out: List[Dict[str, Any]] = []
    for sub in subdirs:
        base = root / sub
        if not base.exists():
            continue
        for p in sorted(base.rglob("*.py")):
            if "__pycache__" in p.parts or ".venv" in p.parts:
                continue
            out.append({"name": str(p.relative_to(root).as_posix()),
                        "path": str(p),
                        "asset_id": f"source:{p.relative_to(root).as_posix()}"})
    return out


def code_capabilities(root: Path) -> Dict[str, set]:
    """Static capability analysis keyed by qualified server.tool name.

    Returns `{}` on any failure rather than raising: a scanner that cannot read the
    code should still produce a declaration-based inventory, and the caller reports
    how many tools got a code-derived profile so the degradation is visible.
    """
    try:
        from codecap import analyze_tree
        # Names are only unique within a server. Never lend a same-named tool
        # another component's source capabilities.
        result = {}
        for module, analysis in analyze_tree(root / 'mcp').items():
            parts = Path(module).parts
            if len(parts) < 2:
                continue
            server = parts[0].replace('_', '-')
            for tool in analysis.tools:
                caps = analysis.caps_for_tool(tool)
                key = f'{server}.{tool}'
                if caps:
                    result.setdefault(key, set()).update(caps)
        return result
    except Exception as e:  # noqa: BLE001
        print(f"[scan] code capability analysis unavailable: {type(e).__name__}: {e}")
        return {}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/evidence/inventory.json")
    ap.add_argument("--docker-filter", default="agentrange")
    ap.add_argument("--skills-root", default=None,
                    help="directory containing one subdirectory per skill")
    ap.add_argument("--range-root", default="/range",
                    help="mount point of the deployment source, for rebasing paths")
    ap.add_argument("--evidence-dir", default="/evidence",
                    help="gateway evidence; used to find tools that are called but "
                         "never declared (a hidden-tool check no per-component scan can do)")
    ap.add_argument("--scan-sources", action="store_true", default=True,
                    help="read the deployable source for behavioural backdoors")
    ap.add_argument("--no-scan-sources", dest="scan_sources", action="store_false")
    ap.add_argument("--mcp", default=None, help="JSON dict of name -> url, overrides defaults")
    a = ap.parse_args()

    mcp = json.loads(a.mcp) if a.mcp else DEFAULT_MCP
    ccaps = code_capabilities(Path(a.range_root)) if a.scan_sources else {}
    graph, raw = scan(docker_name_filter=a.docker_filter,
                      skills_root=a.skills_root, mcp_targets=mcp, code_caps=ccaps)
    raw["n_tools_with_code_profile"] = len(ccaps)

    sources = collect_sources(Path(a.range_root)) if a.scan_sources else []
    if a.scan_sources:
        from source_registry import enrich_registry
        enrich_registry(graph, Path(a.range_root), ccaps)
        from source_profiles import enrich
        enrich(graph, Path(a.range_root))
    findings = assess(graph, read_file_factory(Path(a.range_root)),
                      evidence_dir=a.evidence_dir, sources=sources)
    # Refuted local claims remain observable with their evidence and narrow scope.
    # Unknown claims remain risk candidates. Neither uses evaluation labels.
    observations = [f for f in findings if f.evidence.get('status') == 'source-refuted-scope']
    findings = [f for f in findings if f.evidence.get('status') != 'source-refuted-scope']

    doc: Dict[str, Any] = {
        "asset_graph": graph.to_json(),
        "risks": [f.to_json() for f in findings],
        "observations": [f.to_json() for f in observations],
        "scan_meta": {"elapsed_s": raw.get("elapsed_s"),
                      "n_containers": raw.get("n_containers"),
                      "n_mcp_probed": len(raw.get("mcp_probes") or []),
                      "n_skills": len(raw.get("skills") or [])},
    }
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")

    print("=" * 96)
    print("ASSET INVENTORY")
    print("=" * 96)
    for kind, n in sorted(graph.summary().items()):
        print(f"  {kind:<16}{n:>5}")
    print(f"  {'edges':<16}{len(graph.edges):>5}")
    print()
    print("  -- MCP servers probed --")
    for p in raw.get("mcp_probes") or []:
        n = len(p.get("tools") or [])
        err = p.get("error")
        print(f"     {p['name']:<16} tools_declared={n:<3} {('ERR: ' + err[:50]) if err else ''}")
    print()
    print(f"\n  -- CODE-DERIVED CAPABILITIES ({raw.get('n_tools_with_code_profile', 0)} tools) --")
    for t in sorted(ccaps):
        print(f"     {t:<20}{sorted(ccaps[t])}")
    print()
    print("  -- RISK FINDINGS --")
    by_rule: Dict[str, int] = {}
    for f in findings:
        by_rule[f.risk_id] = by_rule.get(f.risk_id, 0) + 1
    for k, v in sorted(by_rule.items(), key=lambda x: -x[1]):
        print(f"     {k:<38}{v:>4}")
    print()
    for f in findings:
        print(f"     [{f.severity:<6}] {f.risk_id:<34} {f.summary[:88]}")
    for f in observations:
        print(f"     [observed] {f.risk_id:<34} source-refuted within {f.evidence['refutation_scope']}")
    print("=" * 96)
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
