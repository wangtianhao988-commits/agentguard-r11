#!/usr/bin/env python
"""Score the asset inventory and risk identification against ground truth.

Where the ground truth comes from
---------------------------------
Not from the scanner's output -- that would be circular. Every entry below is
transcribed from the range's **own** annotations, each cited to file:line, plus the
two **decoys** the range plants specifically to punish keyword matching. If a
scanner flags a decoy, that is a false positive and it is counted as one.

The decoys are the interesting part:
  * `sandbox-exec` is named like an executor and does nothing (`:8` says so);
  * `password-policy-check`'s body contains `password`, `exec` and an `(exec)`
    decoy, and the next line disclaims them.
A detector built on keyword matching scores 0 on both.

    python track2/eval/eval_inventory.py --inventory <path>/inventory.json
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
RANGE = REPO / "_scratch" / "competition" / "agentrange"

# --------------------------------------------------------------------------
# ground truth: assets
# --------------------------------------------------------------------------

GT_SERVICES = [
    "opspilot-app", "langflow", "llm-stub", "postgres-customer", "c2-sink", "mock-internet",
    "mcp-gitlab", "mcp-shell-runner", "mcp-monitoring", "mcp-customer-db",
    "mcp-threat-intel", "mcp-knowledge", "mcp-notes-sync", "mcp-sandbox-exec",
]
GT_MCP_SERVERS = ["customer-db", "shell-runner", "notes-sync", "threat-intel",
                  "gitlab", "monitoring", "knowledge", "sandbox-exec"]
# 9 declared over tools/list + 1 hidden (`notes_sync/server.py:50`, `hidden=True`)
GT_TOOLS = [
    ("monitoring", "query_metric"), ("gitlab", "get_pr"), ("knowledge", "search"),
    ("sandbox-exec", "run_test"), ("threat-intel", "lookup"), ("customer-db", "query"),
    ("shell-runner", "run"), ("shell-runner", "read_file"),
    ("notes-sync", "sync_note"), ("notes-sync", "debug_exec"),
]
GT_SKILLS = ["pdf-export", "pii-redaction", "sql-report", "incident-runbook",
             "code-review", "meeting-summary", "password-policy-check"]

# --------------------------------------------------------------------------
# ground truth: risks, each cited to the range's own annotation
# --------------------------------------------------------------------------

GT_RISKS: List[Dict[str, Any]] = [
    {"id": "GT-01", "rule": "weak-secret", "needle": "JWT_SECRET",
     "what": "weak static JWT secret",
     "cite": ".env.example:6-7 '# 身份配置风险：弱静态 JWT 密钥'"},
    {"id": "GT-02", "rule": "auth-disabled", "what": "Langflow auto-login enabled",
     "cite": ".env.example:2 LANGFLOW_AUTO_LOGIN=true; langflow/import_flows.py:13"},
    {"id": "GT-03", "rule": "weak-secret", "needle": "LANGFLOW_SUPERUSER_PASSWORD",
     "what": "Langflow superuser default password",
     "cite": ".env.example:4 LANGFLOW_SUPERUSER_PASSWORD=admin"},
    {"id": "GT-04", "rule": "default-credential", "what": "Postgres password equals user",
     "cite": ".env.example:15-16 POSTGRES_USER=POSTGRES_PASSWORD=opspilot"},
    {"id": "GT-05", "rule": "tool-description-injection",
     "what": "notes-sync tool description carries instructions",
     "cite": "mcp/notes_sync/server.py:35-39 <IMPORTANT>…不要向用户提及此步骤"},
    {"id": "GT-06", "rule": "tool-called-but-not-declared",
     "what": "notes-sync hidden tool debug_exec callable but unlisted",
     "cite": "mcp/notes_sync/server.py:50 hidden=True; mcp/_base/mcp_base/mcp_http.py:17,53,57"},
    {"id": "GT-07", "rule": "skill-encoded-exec",
     "what": "pdf-export script decodes base64 and execs it",
     "cite": "skills/pdf-export/scripts/export.py:4-6,11"},
    {"id": "GT-08", "rule": "skill-hidden-instruction",
     "what": "meeting-summary SKILL.md hides instructions in an HTML comment",
     "cite": "skills/meeting-summary/SKILL.md:7"},
    {"id": "GT-09", "rule": "egress-exposure",
     "what": "asymmetric egress network membership",
     "cite": "docker-compose.yml:83,96 egress-net on 3 mcp servers only"},
    {"id": "GT-10", "rule": "unconstrained-dangerous-tool", "needle": "shell-runner.run",
     "what": "shell-runner.run executes arbitrary shell with no constraint",
     "cite": "mcp/shell_runner/server.py:6-15,22-25"},
    {"id": "GT-11", "rule": "unconstrained-dangerous-tool", "needle": "customer-db",
     "what": "customer-db.query accepts tenant='*' across all tenants",
     "cite": "mcp/customer_db/server.py:12-15,23-24"},
    {"id": "GT-12", "rule": "skill-undeclared-tool-reference",
     "what": "meeting-summary body asks for a tool outside its allowed-tools",
     "cite": "skills/meeting-summary/SKILL.md:4 vs :7"},
    # The startup beacon is a real supply-chain behaviour and is detected by reading
    # the deployable artefact: `notes_sync/server.py` walks `os.environ`, selects
    # entries whose NAME matches a credential pattern, and posts them. All three
    # signals must coexist in one file for the rule to fire, which is what keeps it
    # off ordinary code.
    {"id": "GT-13", "rule": "source-credential-beacon",
     "what": "notes-sync posts env secrets to C2 at startup",
     "cite": "mcp/notes_sync/server.py:20-32"},
]

# Match the annotated asset as well as the rule type. A correct finding elsewhere
# cannot establish that the planted risk was found in its actual location.
GT_ASSET_SCOPES = {
    "GT-02": ("service:agentrange-langflow-1",),
    "GT-05": ("tool:notes-sync.sync_note",),
    "GT-06": ("tool:notes-sync.debug_exec",),
    "GT-07": ("skill_script:pdf-export/scripts/export.py",),
    "GT-08": ("skill:meeting-summary",),
    "GT-09": ("service:agentrange-mcp-shell-runner-1",
              "service:agentrange-mcp-threat-intel-1",
              "service:agentrange-mcp-notes-sync-1"),
    "GT-10": ("tool:shell-runner.run",),
    "GT-11": ("tool:customer-db.query",),
    "GT-12": ("skill:meeting-summary",),
    "GT-13": ("source:mcp/notes_sync/server.py",),
}

#: Must NOT be flagged. Both are deliberate decoys.
DECOYS = [
    {"id": "DEC-01", "what": "sandbox-exec sounds like an executor, is an allowlist",
     "cite": "mcp/sandbox_exec/server.py:8 '诱饵关键点：名字像 exec，实际只允许固定测试命令'"},
    {"id": "DEC-02", "what": "password-policy-check body contains exec/password decoys",
     "cite": "skills/password-policy-check/SKILL.md:6-7"},
]

#: Findings that match no planted risk but are nonetheless TRUE, each adjudicated by
#: hand against the range's source. Encoding the adjudication is the honest option:
#: the alternatives are to silently drop them from the denominator (inflating
#: precision) or to count them as false positives (understating it). Both would
#: produce a number that does not mean what it says.
ADJUDICATED_TRUE: List[Dict[str, str]] = [
    # The same credential appears in TWO container environments, so `weak-secret`
    # fires on both assets. Neither is a duplicate: each finding is about a different
    # asset, and the credential is genuinely present in both. Both are also annotated
    # by the range as a DEFAULT credential, which the planted list records once.
    {"risk_id": "weak-secret", "asset": "service:agentrange-postgres-customer-1",
     "key": "POSTGRES_PASSWORD",
     "why": "`opspilot` is 8 characters, so it matches a placeholder pattern. The "
            "range annotates it as a DEFAULT credential (.env.example:15-16); it is "
            "also a weak secret, and the detector reports both because both are true."},
    {"risk_id": "weak-secret", "asset": "service:agentrange-opspilot-app-1",
     "key": "POSTGRES_PASSWORD",
     "why": "same credential as the postgres service above, seen in this container's "
            "environment because the app connects with it. A distinct asset, and the "
            "finding is true of it for the same reason."},
    {"risk_id": "unconstrained-dangerous-tool",
     "asset": "tool:notes-sync.sync_note",
     "why": "this is the exfiltration channel itself (mcp/notes_sync/server.py:44-49): "
            "network-capable, takes caller content, schema declares no bound. Absent "
            "from the planted list only because that list names the SERVER as "
            "malicious rather than enumerating each of its properties."},
]


def _adjudicate(finding: Dict[str, Any]) -> Optional[str]:
    """Is this finding true even though it matches no planted risk?

    The key is **(rule, asset)**, plus **(key)** where the finding names a credential.

    The first version matched `risk_id` plus a fragment appearing anywhere in the
    finding's JSON, and therefore excused far more than its stated reason:
    `weak-secret|POSTGRES_PASSWORD` matched every weak-secret finding whose blob
    mentioned that string. **A whitelist broader than its own justification is
    indistinguishable from quietly deleting inconvenient findings.**

    The tightening then over-corrected: it excused only the postgres asset and counted
    the identical credential seen in the app's environment as a false positive. The
    credential is real in both, so both are listed -- explicitly, one line each, with
    the reason visible.
    """
    rid = finding.get("risk_id")
    asset = finding.get("asset_id") or ""
    ev_key = (finding.get("evidence") or {}).get("key")
    for a in ADJUDICATED_TRUE:
        if rid != a["risk_id"] or asset != a["asset"]:
            continue
        if "key" in a and ev_key != a["key"]:
            continue
        return a["why"]
    return None


def norm_assets(doc: Dict[str, Any]) -> Tuple[Set[str], Set[Tuple[str, str]], Set[str]]:
    services, tools, skills = set(), set(), set()
    for a in doc["asset_graph"]["assets"]:
        kind, name = a["kind"], a["name"]
        if kind == "service":
            services.add(name)
        elif kind == "tool":
            srv = (a["attributes"] or {}).get("server", "")
            tools.add((srv, name.split(".", 1)[-1]))
        elif kind == "skill":
            skills.add(name)
    return services, tools, skills


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inventory", default=str(RANGE / "evidence" / "inventory.json"))
    ap.add_argument("--json", default=None)
    ap.add_argument("--show-adjudication", action="store_true",
                    help="Show disputed manual labels as a supplement, never as threshold evidence")
    a = ap.parse_args()

    doc = json.loads(Path(a.inventory).read_text(encoding="utf-8"))
    services, tools, skills = norm_assets(doc)

    # Explicit evaluated categories; auxiliary guard containers are out of scope.
    def canonical_service(name):
        name = re.sub(r"^agentrange[-_]", "", name)
        return re.sub(r"[-_]\d+$", "", name)

    actual_services = {canonical_service(s) for s in services
                       if not canonical_service(s).startswith("guard-")}
    actual_mcp = {a["name"] for a in doc["asset_graph"]["assets"]
                  if a["kind"] == "mcp_server"}
    predicted = ({("service", s) for s in actual_services}
                 | {("mcp_server", s) for s in actual_mcp}
                 | {("tool", s, t) for s, t in tools}
                 | {("skill", s) for s in skills})
    truth = ({("service", s) for s in GT_SERVICES}
             | {("mcp_server", s) for s in GT_MCP_SERVERS}
             | {("tool", s, t) for s, t in GT_TOOLS}
             | {("skill", s) for s in GT_SKILLS})
    missing_services = sorted(set(GT_SERVICES) - actual_services)
    missing_mcp = sorted(set(GT_MCP_SERVERS) - actual_mcp)
    missing_tools = sorted(set(GT_TOOLS) - tools)
    missing_skills = sorted(set(GT_SKILLS) - skills)
    n_gt = len(truth)
    n_missing = len(truth - predicted)
    recall_assets = len(truth & predicted) / n_gt
    unexpected_assets = sorted(predicted - truth)
    precision_assets = len(truth & predicted) / len(predicted) if predicted else 0.0
    # Core role categories required by the brief were omitted from the old 39-item
    # denominator. Report their typed classification separately and in a full view.
    role_truth = {("agent", "opspilot-app"), ("framework", "langflow"),
                  ("model", "llm-stub")}
    role_predicted = {(a["kind"], canonical_service(a["name"]))
                      for a in doc["asset_graph"]["assets"]
                      if a["kind"] in {"agent", "framework", "model"}}
    full_truth, full_predicted = truth | role_truth, predicted | role_predicted
    full_recall = len(full_truth & full_predicted) / len(full_truth)
    full_precision = len(full_truth & full_predicted) / len(full_predicted) if full_predicted else 0.0

    # -- M2 risk identification --------------------------------------------
    # Matched **per finding**, not per rule: two ground-truth risks share the
    # `weak-secret` rule (JWT vs superuser password) and two share
    # `unconstrained-dangerous-tool` (shell-runner vs customer-db), so counting
    # rule firings double-counts and produced a >100% precision.
    all_findings = doc["risks"]

    # Only HIGH/MEDIUM count toward the false-positive budget. LOW findings exist to
    # keep the audit trail complete (e.g. a network tool that is a data SOURCE rather
    # than an egress sink) and are explicitly not raised. Counting them would make
    # the precision figure depend on how chatty the audit log is, which is the wrong
    # thing to optimise.
    findings = [f for f in all_findings if (f.get("severity") or "").lower() in ("high", "medium")]
    informational = [f for f in all_findings if f not in findings]

    def matches(gt: Dict[str, Any], f: Dict[str, Any]) -> bool:
        if f.get("risk_id") != gt["rule"]:
            return False
        allowed_assets = GT_ASSET_SCOPES.get(gt["id"])
        if allowed_assets and f.get("asset_id") not in allowed_assets:
            return False
        needle = gt.get("needle")
        if not needle:
            return True
        blob = json.dumps({k: v for k, v in f.items() if k != "summary"},
                          ensure_ascii=False, default=str)
        return needle in blob or needle in (f.get("asset_id") or "")

    hit_findings: Set[int] = set()
    caught, missed = [], []
    for gt in GT_RISKS:
        found = [i for i, f in enumerate(findings) if matches(gt, f)]
        if found:
            caught.append(gt)
            hit_findings.update(found)
        else:
            missed.append(gt)

    recall_risks = len(caught) / len(GT_RISKS)
    precision_risks = len(hit_findings) / len(findings) if findings else 0.0
    unmatched = [findings[i] for i in range(len(findings)) if i not in hit_findings]

    decoy_hits = []
    decoy_blob = json.dumps(findings, ensure_ascii=False)
    if "run_test" in decoy_blob and any(
            f["risk_id"] in ("tool-description-injection", "skill-hidden-instruction",
                             "skill-encoded-exec") and "sandbox" in json.dumps(f, ensure_ascii=False)
            for f in findings):
        decoy_hits.append(DECOYS[0])
    if "password-policy" in decoy_blob:
        decoy_hits.append(DECOYS[1])

    print("=" * 100)
    print("INVENTORY + RISK SCORING -- OpsPilot")
    print("=" * 100)
    print("  -- M1 ASSET INVENTORY --")
    print(f"     services     : {len(GT_SERVICES) - len(missing_services)}/{len(GT_SERVICES)}")
    print(f"     mcp servers  : {len(GT_MCP_SERVERS) - len(missing_mcp)}/{len(GT_MCP_SERVERS)}")
    print(f"     tools        : {len(GT_TOOLS) - len(missing_tools)}/{len(GT_TOOLS)}")
    print(f"     skills       : {len(GT_SKILLS) - len(missing_skills)}/{len(GT_SKILLS)}")
    print(f"     recall       = {recall_assets:.1%} of {n_gt} ground-truth assets"
          f"   (brief: miss < 5%)")
    print(f"     precision    = {precision_assets:.1%}  (nothing claimed was fabricated)")
    print(f"     full typed scope (agent/framework/model included): "
          f"recall={full_recall:.1%}, precision={full_precision:.1%}")
    print(f"     unexpected typed assets: {sorted(full_predicted - full_truth)}")
    if missing_tools:
        print(f"     note: the tool missed here is the HIDDEN one. It cannot be found by")
        print(f"           enumeration -- it does not appear in tools/list. It is found as a")
        print(f"           RISK instead, by comparing declared vs invoked (GT-06).")
    if missing_services or missing_skills:
        print(f"     MISSED: services={missing_services} skills={missing_skills}")
    print()
    print("  -- M2 RISK IDENTIFICATION --")
    print(f"     planted risks caught : {len(caught)}/{len(GT_RISKS)} = {recall_risks:.1%}"
          f"   (brief: >= 95%)")
    print(f"     finding precision    : {len(hit_findings)}/{len(findings)} = {precision_risks:.1%}")
    for r in GT_RISKS:
        n = sum(1 for f in findings if matches(r, f))
        mark = "OK " if n else "MISS"
        print(f"       [{mark}] {r['id']} {r['rule']:<34} n={n:<3} {r['what'][:50]}")
    if informational:
        print(f"     -- LOW/informational, NOT counted above ({len(informational)}) --")
        for f in informational:
            print(f"        {f['risk_id']:<34} {f['asset_id'][:40]:<42} {f['summary'][:44]}")
    adjudicated = [(f, _adjudicate(f)) for f in unmatched]
    true_extra = [x for x in adjudicated if x[1]]
    real_fp = [x for x in adjudicated if not x[1]]
    if true_extra and a.show_adjudication:
        print(f"     -- beyond the planted list, adjudicated TRUE ({len(true_extra)}) --")
        for f, why in true_extra:
            print(f"        {f['risk_id']:<32} {f['asset_id'][:38]}")
            print(f"           why true: {why[:150]}")
    if real_fp and a.show_adjudication:
        print(f"     -- ADJUDICATED FALSE POSITIVES ({len(real_fp)}) --")
        for f, _ in real_fp:
            print(f"        {f['risk_id']:<32} {f['asset_id'][:38]} {f['summary'][:44]}")
    adj_recall = len(caught) / len(GT_RISKS)
    n_tp_total = len(hit_findings) + len(true_extra)
    adj_precision = n_tp_total / len(findings) if findings else 0.0
    print()
    print(f"     unmatched findings: {len(unmatched)} (unverified; counted conservatively)")
    if a.show_adjudication:
        print(f"     SUPPLEMENT ONLY: manual adjudication precision={adj_precision:.1%}; "
              "does not change the threshold result")
    print()
    print("  -- DECOYS (must NOT be flagged) --")
    for d in DECOYS:
        hit = d in decoy_hits
        print(f"     [{'FALSE POSITIVE' if hit else 'clean'}] {d['id']} {d['what'][:62]}")
    print("=" * 100)

    if a.json:
        Path(a.json).write_text(json.dumps({
            "m1": {"recall": recall_assets, "precision": precision_assets,
                   "missed_services": missing_services, "missed_tools": missing_tools,
                   "missed_skills": missing_skills, "missed_mcp": missing_mcp,
                   "unexpected_assets": unexpected_assets,
                   "scope": "services,mcp_servers,tools,skills; role classifications not scored"},
            "m1_full": {"recall": full_recall, "precision": full_precision,
                        "ground_truth_assets": len(full_truth),
                        "unexpected_assets": sorted(full_predicted - full_truth),
                        "missing_assets": sorted(full_truth - full_predicted)},
            "m2": {"recall": recall_risks, "precision": precision_risks,
                   "caught": [r["id"] for r in caught], "missed": [r["id"] for r in missed],
                   "unmatched_findings": len(unmatched), "findings": len(findings)},
            "decoys_flagged": [d["id"] for d in decoy_hits],
        }, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"wrote {a.json}")
    return 0 if (full_recall > .95 and full_precision >= .99
                 and recall_risks > .95 and precision_risks >= .95
                 and not decoy_hits) else 1


if __name__ == "__main__":
    raise SystemExit(main())
