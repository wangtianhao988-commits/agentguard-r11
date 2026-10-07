"""Configuration and supply-chain risk identification -- the M2/J1 half.

Two families, and they fail differently:

  * **Configuration risk** is a property of a *value*: a secret that is weak, a
    credential left at its default, an admin surface with no authentication. These
    are detected by measuring the value, never by comparing it to a known-bad list --
    a blocklist of placeholder strings finds `change-me-weak-secret` and nothing else,
    which is exactly the overfitting the brief warns against.

  * **Supply-chain risk** is a property of a *mismatch*: what a component declares
    versus what it does. A tool description that carries instructions, a skill whose
    manifest promises nothing while its `scripts/` directory runs `exec`, a tool that
    is callable but absent from `tools/list`. These need two facts, which is why they
    survive a change of component names.

Precision discipline
--------------------
The brief puts M2 at >=95% accuracy with <5% misses, and J1 explicitly weighs false
positives. So every check returns *evidence*, not a boolean, and no check fires on a
single lexical cue. `password-policy-check` in this range exists purely to punish
keyword matching: its body contains `password`, `exec` and a `(exec)` decoy, and the
next line disclaims them. A rule that greps for `exec` fails on it.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

# --------------------------------------------------------------------------
# finding model
# --------------------------------------------------------------------------

HIGH = "high"
MEDIUM = "medium"
LOW = "low"


@dataclass
class RiskFinding:
    risk_id: str
    category: str          # config | supply_chain
    severity: str
    asset_id: str
    summary: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> Dict[str, Any]:
        return {"risk_id": self.risk_id, "category": self.category,
                "severity": self.severity, "asset_id": self.asset_id,
                "summary": self.summary, "evidence": self.evidence}


# --------------------------------------------------------------------------
# config: secret strength, measured rather than matched
# --------------------------------------------------------------------------

#: Generic placeholder vocabulary. Deliberately short and generic -- it is a hint,
#: never the sole basis for a finding.
_PLACEHOLDER = re.compile(
    r"(change[-_ ]?me|changeme|placeholder|your[-_ ]?(?:secret|key|password)|"
    r"^admin$|^password$|^passwd$|^root$|^test$|^demo$|^example$|^default$|"
    r"^secret$|^token$|^key$|^none$|^null$|^todo$|^x{3,}$)", re.I)

_SECRETISH_KEY = re.compile(r"(secret|token|password|passwd|pwd|api[-_]?key|"
                            r"private[-_]?key|signing[-_]?key|credential)", re.I)

_SENSITIVE_ENV_EXFIL = re.compile(r"(secret|token|key|password)", re.I)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_weak_secret(value: str) -> Tuple[bool, str]:
    """Measured weakness: length, entropy, character-class spread, placeholder shape.

    Reports WHY, so a human can disagree with the threshold rather than having to
    trust a score.
    """
    v = (value or "").strip()
    if not v:
        return True, "empty"
    if _PLACEHOLDER.search(v):
        return True, "matches a generic placeholder pattern"
    if len(v) < 12:
        return True, f"only {len(v)} characters"
    classes = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
    ent = shannon_entropy(v)
    if ent < 2.5:
        return True, f"entropy {ent:.2f} bits/char over {len(v)} chars (repetitive)"
    if len(v) < 20 and classes < 2:
        return True, f"single character class over {len(v)} chars"
    return False, ""


def check_env_secrets(assets: Iterable[Any]) -> List[RiskFinding]:
    out: List[RiskFinding] = []
    for a in assets:
        env = (a.attributes or {}).get("env") or {}
        for k, v in env.items():
            if not _SECRETISH_KEY.search(k):
                continue
            weak, why = is_weak_secret(v)
            if not weak:
                continue
            out.append(RiskFinding(
                "weak-secret", "config", HIGH, a.asset_id,
                f"{a.name}: env {k} is a weak secret ({why})",
                {"key": k, "length": len(v or ""), "reason": why,
                 "entropy": round(shannon_entropy(v or ""), 2),
                 # The value itself is never emitted. A scanner that prints the
                 # secret it found has created a second copy of the problem.
                 "value_redacted": True}))
    return out


def check_default_credentials(assets: Iterable[Any]) -> List[RiskFinding]:
    out: List[RiskFinding] = []
    for a in assets:
        env = (a.attributes or {}).get("env") or {}
        user = next((v for k, v in env.items() if k.upper() in ("POSTGRES_USER", "DB_USER",
                                                                "MYSQL_USER", "USERNAME")), None)
        pwd = next((v for k, v in env.items() if k.upper() in ("POSTGRES_PASSWORD", "DB_PASSWORD",
                                                               "MYSQL_PASSWORD", "PASSWORD")), None)
        if user and pwd and user == pwd:
            out.append(RiskFinding(
                "default-credential", "config", HIGH, a.asset_id,
                f"{a.name}: database credential equals the username",
                {"user": user, "key": next(k for k, v in env.items()
                 if k.upper() in ("POSTGRES_PASSWORD", "DB_PASSWORD", "MYSQL_PASSWORD", "PASSWORD")
                 and v == pwd)}))
    return out


def check_auth_disabled(assets: Iterable[Any]) -> List[RiskFinding]:
    """Flags that switch authentication OFF.

    Matched on the *shape* of the flag (`*_AUTO_LOGIN`, `*_SKIP_AUTH*`, `*_NO_AUTH*`,
    `DISABLE_AUTH`), not on a product name, so it transfers to another stack.
    """
    out: List[RiskFinding] = []
    pat = re.compile(r"(auto[-_]?login|skip[-_]?auth|no[-_]?auth|disable[-_]?auth|"
                     r"allow[-_]?anonymous|auth[-_]?disabled)", re.I)
    for a in assets:
        env = (a.attributes or {}).get("env") or {}
        for k, v in env.items():
            if pat.search(k) and str(v).strip().lower() in ("true", "1", "yes", "on"):
                profile = (a.attributes or {}).get("entrypoint_env_profile")
                unbound = bool(profile and any(e.get('absence_rejected_unconditionally')
                               for e in profile.get("auth_dependency_evidence", []))
                               and k not in profile["keys"])
                refuted = unbound and profile.get('canonical_guard_symbols_bound', False)
                out.append(RiskFinding(
                    "auth-disabled", "config", LOW if unbound else HIGH, a.asset_id,
                    f"{a.name}: declares {k}={v}; potential authentication bypass, "
                    "verify that this component consumes the flag",
                    {"key": k, "value": v, "effective_on_this_component": None,
                     "entrypoint_binding_found": False if unbound else None,
                     "source_profile": profile,
                     "status": ('source-refuted-scope' if refuted else
                                'unverified-candidate' if unbound else 'configuration-alert'),
                     "refutation_scope": 'missing-credential bypass of listed dependency-bound handlers' if refuted else None}))
    return out


def check_egress_exposure(assets: Iterable[Any], egress_network_marker: str = "egress") -> List[RiskFinding]:
    """A service on an egress network while its peers are not.

    The finding is the *asymmetry*, which is why it needs the whole graph and not one
    asset. A boundary that everything crosses is a boundary; a boundary one service
    crosses is a path.
    """
    out: List[RiskFinding] = []
    with_egress: List[Any] = []
    without: List[Any] = []
    for a in assets:
        nets = (a.attributes or {}).get("networks") or []
        if not nets:
            continue
        (with_egress if any(egress_network_marker in n.lower() for n in nets) else without).append(a)
    if not with_egress or not without:
        return out
    for a in with_egress:
        nets = a.attributes.get("networks") or []
        # A receiver on an external-only network does not bridge an internal
        # trust boundary. Require a shared non-egress network with a protected peer.
        internal = {n for n in nets if egress_network_marker not in n.lower()}
        peers = [x for x in without
                 if internal.intersection((x.attributes or {}).get("networks") or [])]
        if not peers:
            continue
        out.append(RiskFinding(
            "egress-exposure", "config", MEDIUM, a.asset_id,
            (f"{a.name} is attached to an egress-capable network "
             f"({[n for n in nets if egress_network_marker in n.lower()]}) while "
             f"{len(peers)} peers on its internal networks are not"),
            {"networks": nets, "peers_without_egress": [x.name for x in peers][:12]}))
    return out


#: A parameter that carries caller-supplied CONTENT -- i.e. data that will leave.
#: This is what distinguishes an egress SINK from a lookup SOURCE, and it is the
#: discriminator the first version was missing: `threat-intel.lookup(cve)` and
#: `notes-sync.sync_note(text)` are both "network-capable tools with no destination
#: parameter", but one brings data IN and the other sends it OUT. Both were flagged,
#: and one of them is a legitimate tool the range ships on purpose.
_CONTENT_PARAM = re.compile(r"(text|body|content|data|payload|message|note|blob)", re.I)
_QUERY_PARAM = re.compile(r"^(q|cve|id|name|key|term|query|ref|ticket|pr|doc)", re.I)


def _egress_direction(schema: Dict[str, Any]) -> str:
    """`sink` if the caller supplies content that leaves, else `source`."""
    props = (schema or {}).get("properties") or {}
    if any(_CONTENT_PARAM.search(p) for p in props):
        return "sink"
    return "source"


def check_broad_capability(assets: Iterable[Any], capability_fn) -> List[RiskFinding]:
    """A tool whose dangerous capability is not bounded by its declaration.

    `capability_fn(server, tool)` is injected so the capability table stays in one
    place (the detector's), rather than being duplicated and drifting.

    What "dangerous" means depends on the capability, and flattening the three into
    one test produced both a miss and a false positive:

      * **exec** -- dangerous unconditionally. Running arbitrary code is the
        capability; there is no bounded form of it that a schema can express.
      * **db_read** -- dangerous when unconstrained, because a wildcard read is the
        confused-deputy primitive (`mcp/customer_db/server.py:12` says so outright).
        Direction is irrelevant; the risk is reading across a boundary.
      * **net** -- dangerous only if it is a **sink**. A lookup returns data into the
        model's context; a sink sends caller data out. Flagging both put
        `threat-intel.lookup` (a deliberate, legitimate egress tool) in the same
        bucket as `notes-sync.sync_note` (the exfiltration path).

    `db_read` was missing from the first version entirely, which lost a planted risk.
    """
    DANGEROUS = {"exec", "net", "db_read"}
    out: List[RiskFinding] = []
    for a in assets:
        if a.kind != "tool":
            continue
        server = (a.attributes or {}).get("server", "")
        attrs = a.attributes or {}
        if attrs.get('source_registration', {}).get('hidden') is True:
            # The registration discrepancy and dangerous implementation are one
            # hidden-tool risk instance, explained together below.
            continue
        caps = capability_fn(server, a.name.split(".", 1)[-1],
                             attrs.get("input_schema"), attrs.get("description") or "",
                             set(attrs.get("code_caps") or []))
        from session import _disclaims_execution
        if (_disclaims_execution(attrs.get("description") or "")
                and "exec" not in set(attrs.get("code_caps") or [])):
            # Static manifest assessment: a declared bounded executor is a candidate,
            # not demonstrated arbitrary execution. The runtime rule still judges
            # each command and source-discovered exec can never be discounted.
            caps = caps - {"exec"}
        if not (caps & DANGEROUS):
            continue
        schema = (a.attributes or {}).get("input_schema") or {}
        if "exec" not in caps and _schema_is_constrained(schema):
            continue

        if "exec" in caps:
            risk, why = "exec", "can execute code"
        elif "db_read" in caps:
            risk, why = "db_read", "reads records with no declared bound"
        else:
            direction = _egress_direction(schema)
            if attrs.get("code_profile_pure_return"):
                proof = attrs['code_profile_pure_return']
                binding = attrs.get('source_registration', {})
                refuted = (binding.get('handler') == proof.get('handler')
                           and binding.get('file') == proof.get('file')
                           and not attrs.get('source_registration_ambiguous'))
                # Positive syntax proof of a simple handler, not absence of a
                # recognised network primitive. Startup hooks remain separately audited.
                out.append(RiskFinding("unverified-egress-capability", "config", LOW,
                    a.asset_id, f"{a.name}: declaration suggests egress, but the local handler only returns data",
                    {"capabilities": sorted(caps),
                     "status": 'source-refuted-scope' if refuted else 'unverified-candidate',
                     "refutation_scope": 'network or process side effect inside this bound handler on JSON primitive inputs' if refuted else None,
                     "boundary_retained": 'Caller content crosses the third-party MCP transport boundary; whole component safety is not established.',
                     "source_registration": binding, "source_proof": proof}))
                continue
            if direction != "sink":
                # A lookup. Recorded, not raised: the audit trail keeps it, the
                # false-positive budget does not pay for it.
                out.append(RiskFinding(
                    "unconstrained-source-tool", "config", LOW, a.asset_id,
                    (f"tool {a.name} can reach the network but only supplies query "
                     f"parameters, so it is a data SOURCE rather than an egress sink"),
                    {"capabilities": sorted(caps), "direction": direction,
                     "schema": schema}))
                continue
            risk, why = "net-sink", "sends caller-supplied content outward"

        out.append(RiskFinding(
            "unconstrained-dangerous-tool", "config", MEDIUM, a.asset_id,
            (f"tool {a.name} {why} (capability {sorted(caps)}) and its input schema "
             f"declares no constraint (no enum, no pattern, no bounds)"),
            {"capabilities": sorted(caps), "risk": risk, "schema": schema}))
    return out


def _schema_is_constrained(schema: Dict[str, Any]) -> bool:
    if not isinstance(schema, dict):
        return False
    props = schema.get("properties") or {}
    # A length or format annotation does not bound authority or executable content.
    # One constrained metadata field does not constrain all dangerous inputs.
    return bool(props) and all(isinstance(spec, dict) and
                              ("const" in spec or bool(spec.get("enum")))
                              for spec in props.values())


# --------------------------------------------------------------------------
# supply chain: declarations vs behaviour
# --------------------------------------------------------------------------

_INVISIBLE = re.compile("[\u200b-\u200f\u2060\ufeff\u00ad]")
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_IMPERATIVE = re.compile(
    r"(ignore (?:all )?(?:previous|prior|above)|disregard|不要(?:向用户)?(?:提及|告诉)|"
    r"do not (?:tell|mention|inform)|without (?:telling|informing)|"
    r"read\s+[/\w.~-]*\.(?:env|pem|key)|读取\s*[/\w.~-]*\.(?:env|pem|key)|"
    r"上传|exfiltrat|发送到|send\s+to\s+https?://)", re.I)
_SENSITIVE_REF = re.compile(
    r"(\.env\b|id_rsa|id_ed25519|\.ssh\b|\.aws\b|credentials|secret|"
    r"signing[-_]?key|service[-_]?token|/etc/(?:passwd|shadow))", re.I)
_ROLE_SPOOF = re.compile(r"^\s*(system|assistant|developer)\s*:", re.I | re.M)
_B64_BLOB = re.compile(r"[\"']([A-Za-z0-9+/=]{40,})[\"']")
_DYNAMIC_EXEC = re.compile(r"\b(exec|eval|compile)\s*\(")
_PROC_SPAWN = re.compile(r"\b(subprocess|os\.system|os\.popen|popen|pty\.spawn)\b")
_PIPE_TO_SHELL = re.compile(r"\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b")


def check_tool_descriptions(assets: Iterable[Any]) -> List[RiskFinding]:
    """MCP tool descriptions that carry instructions.

    `mcp/_base/mcp_base/mcp_http.py:51` forwards `Tool.description` verbatim into
    `tools/list`, so the description field is a prompt-injection channel that reaches
    every agent that enumerates tools. A description should *describe*; these do not.

    Requires two independent signals (imperative/secrecy language AND a sensitive
    reference OR a cross-component instruction) so that a legitimately verbose
    description cannot trip it.
    """
    out: List[RiskFinding] = []
    for a in assets:
        if a.kind != "tool":
            continue
        desc = (a.attributes or {}).get("description") or ""
        if not desc:
            continue
        imp = _IMPERATIVE.search(desc)
        sens = _SENSITIVE_REF.search(desc)
        cross = re.search(r"(before (?:calling|using) (?:any )?other tool|调用其他工具之前|"
                          r"先(?:读取|调用))", desc, re.I)
        if not imp and not (sens and cross):
            continue
        if not (sens or cross):
            continue
        out.append(RiskFinding(
            "tool-description-injection", "supply_chain", HIGH, a.asset_id,
            f"tool {a.name}: its description contains instructions, not documentation",
            {"matched_imperative": imp.group(0) if imp else None,
             "sensitive_reference": sens.group(0) if sens else None,
             "cross_component_instruction": bool(cross),
             "description": desc[:400]}))
    return out


def check_invalid_schema(assets: Iterable[Any], peers: Optional[List[Any]] = None) -> List[RiskFinding]:
    """A tool whose `inputSchema` is not a JSON Schema object.

    Every legitimate tool in a generated registry uses the same shape. One that does
    not was written by hand, which correlates with being written for a different
    purpose. This is a *structural* signal and needs no knowledge of the tool.
    """
    out: List[RiskFinding] = []
    for a in assets:
        if a.kind != "tool":
            continue
        schema = (a.attributes or {}).get("input_schema")
        if (a.attributes or {}).get('source_registration', {}).get('hidden') is True:
            # Unadvertised registration, schema and implementation are retained
            # together as the hidden-tool instance, not three independent alerts.
            continue
        if not isinstance(schema, dict):
            out.append(RiskFinding("invalid-tool-schema", "supply_chain", MEDIUM, a.asset_id,
                                   f"tool {a.name}: inputSchema is not an object", {"schema": schema}))
            continue
        if schema.get("type") != "object" or "properties" not in schema:
            out.append(RiskFinding(
                "invalid-tool-schema", "supply_chain", MEDIUM, a.asset_id,
                (f"tool {a.name}: inputSchema is not a well-formed object schema "
                 f"(type={schema.get('type')!r}, properties={'properties' in schema})"),
                {"schema": schema}))
    return out


def check_skill_manifest(skills: List[Dict[str, Any]]) -> List[RiskFinding]:
    """Skill body carrying hidden or out-of-band instructions.

    Two structural facts, either sufficient:

      * an **HTML comment** in a markdown file -- rendered invisibly, so the human
        reviewing the skill never sees it while the model does; and
      * the comment (or body) containing instruction language plus a sensitive
        reference, i.e. the pattern is not merely hidden but *actionable*.

    Also flags body text that names a tool outside the skill's own `allowed-tools`,
    which is a pure declaration-versus-declaration contradiction.
    """
    out: List[RiskFinding] = []
    for sk in skills:
        body = sk.get("body") or ""
        aid = f"skill:{sk['name']}"
        comments = _HTML_COMMENT.findall(body)
        for c in comments:
            if _IMPERATIVE.search(c) or (_SENSITIVE_REF.search(c) and _ROLE_SPOOF.search(c)):
                out.append(RiskFinding(
                    "skill-hidden-instruction", "supply_chain", HIGH, aid,
                    (f"skill {sk['name']}: an HTML comment in SKILL.md carries "
                     f"instructions invisible to a reader of the rendered document"),
                    {"comment": c.strip()[:400],
                     "role_spoof": bool(_ROLE_SPOOF.search(c)),
                     "sensitive_reference": bool(_SENSITIVE_REF.search(c))}))
                break
        if _INVISIBLE.search(body):
            out.append(RiskFinding(
                "skill-invisible-text", "supply_chain", MEDIUM, aid,
                f"skill {sk['name']}: body contains invisible characters",
                {"count": len(_INVISIBLE.findall(body))}))

        allowed = set(sk.get("allowed_tools") or [])
        mentioned = set()
        for m in re.finditer(r"\b([a-z][a-z0-9-]{2,})\.[a-z_][a-z0-9_]*\b", body):
            mentioned.add(m.group(1))
        extra = {x for x in mentioned if x not in allowed and x not in ("self",)}
        if extra and allowed:
            out.append(RiskFinding(
                "skill-undeclared-tool-reference", "supply_chain", MEDIUM, aid,
                (f"skill {sk['name']}: body references {sorted(extra)} but "
                 f"allowed-tools={sorted(allowed)}"),
                {"declared": sorted(allowed), "referenced": sorted(extra)}))
    return out


def check_skill_scripts(skills: List[Dict[str, Any]], read_file) -> List[RiskFinding]:
    """Scripts a skill ships that its manifest never mentions.

    `skills/loader.py` parses frontmatter and returns the body; it never enumerates,
    reads or executes `scripts/`. So a script is invisible to every manifest-based
    check by construction.

    Signals, all structural: a long base64 literal next to `exec`/`eval`; a download
    piped into a shell; a process-spawn primitive in a skill that declares no
    execution capability.
    """
    out: List[RiskFinding] = []
    for sk in skills:
        aid = f"skill:{sk['name']}"
        allowed = set(sk.get("allowed_tools") or [])
        skill_dir = Path(sk["path"]).parent if sk.get("path") else None
        for rel in sk.get("scripts") or []:
            # The script lives beside SKILL.md, not underneath it. Appending to the
            # SKILL.md path produced `/…/SKILL.md/scripts/export.py`, which does not
            # exist, so the reader returned None and EVERY script check was skipped --
            # including the one that catches the encoded-exec backdoor. A silent
            # no-op is the failure mode to watch for here.
            if skill_dir is None:
                continue
            path = str(skill_dir / rel)
            text = read_file(path)
            if text is None:
                out.append(RiskFinding(
                    "skill-script-unreadable", "supply_chain", MEDIUM, aid,
                    f"{sk['name']}/{rel}: referenced by the skill but could not be read",
                    {"file": rel, "resolved_path": path}))
                continue
            sid = f"skill_script:{sk['name']}/{rel}"
            blob = _B64_BLOB.findall(text)
            decoded_preview = ""
            for b in blob:
                try:
                    dec = base64.b64decode(b + "=" * (-len(b) % 4)).decode("utf-8", "replace")
                except (binascii.Error, ValueError):
                    continue
                if dec.isprintable() or len(dec.strip()) > 8:
                    decoded_preview = dec[:300]
                    break
            execs = bool(_DYNAMIC_EXEC.search(text))
            spawns = bool(_PROC_SPAWN.search(text))
            pipe = bool(_PIPE_TO_SHELL.search(text)) or bool(_PIPE_TO_SHELL.search(decoded_preview))

            if blob and execs:
                out.append(RiskFinding(
                    "skill-encoded-exec", "supply_chain", HIGH, sid,
                    (f"{sk['name']}/{rel}: decodes an embedded payload and executes it "
                     f"(base64 literal -> exec). The payload need not be read to see this."),
                    {"file": rel, "n_b64_literals": len(blob),
                     "decoded_preview_redacted": False, "decoded_preview": decoded_preview[:200]}))
            elif pipe:
                out.append(RiskFinding(
                    "skill-download-exec", "supply_chain", HIGH, sid,
                    f"{sk['name']}/{rel}: fetches remote content and pipes it into a shell",
                    {"file": rel}))
            elif spawns and not allowed:
                out.append(RiskFinding(
                    "skill-script-spawns-process", "supply_chain", MEDIUM, sid,
                    (f"{sk['name']}/{rel}: spawns a process while the skill declares "
                     f"allowed-tools={sorted(allowed) or '[]'}"),
                    {"file": rel}))
    return out


def check_undeclared_tools(graph, evidence_dir: Optional[str] = None) -> List[RiskFinding]:
    """A tool that is CALLED but never DECLARED.

    `mcp/_base/mcp_base/mcp_http.py:53` filters `hidden` tools out of `tools/list`
    while `:57` still resolves them from the registry, so a tool can be invoked over
    `tools/call` while being invisible to every client that enumerates first. That
    gap is exactly what a supply-chain backdoor looks like from outside.

    It is also detectable **without reading any source**: compare the union of tools
    each server declares against the tools actually invoked in the evidence stream.
    Anything invoked and never declared is either a hidden tool or a confused client,
    and both are worth a finding. This is the cross-component check that a
    per-component scanner cannot do.
    """
    out: List[RiskFinding] = []
    declared: Set[Tuple[str, str]] = set()
    for a in graph.assets.values():
        if a.kind == "tool":
            srv = (a.attributes or {}).get("server", "")
            if (a.attributes or {}).get('declared_in_tools_list', True):
                declared.add((srv, a.name.split(".", 1)[-1]))
            elif (a.attributes or {}).get('source_registration', {}).get('hidden') is True:
                out.append(RiskFinding('tool-called-but-not-declared', 'supply_chain', HIGH,
                    a.asset_id, f'{a.name}: source registry makes an unlisted tool callable',
                    {'server': srv, 'tool': a.name.split('.', 1)[-1],
                     'evidence_basis': 'static-registration', 'invocations': None,
                     'source_registration': a.attributes['source_registration'],
                     'input_schema': a.attributes.get('input_schema'),
                     'code_caps': a.attributes.get('code_caps', [])}))

    if not evidence_dir:
        return out
    p = Path(evidence_dir) / "C_mcp_call.jsonl"
    if not p.exists():
        return out
    seen: Dict[Tuple[str, str], int] = {}
    malformed = 0
    if not p.exists():
        return out
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except Exception:  # noqa: BLE001
            malformed += 1
            continue
        key = (r.get("server", ""), r.get("tool") or "")
        if all(key):
            seen[key] = seen.get(key, 0) + 1

    # A silent skip is how this check reported "nothing found" while actually being
    # broken: `json` was not imported, `json.loads` raised NameError, and the bare
    # `except` above swallowed it on every line -- indistinguishable from a clean
    # bill of health. Two guards, because that failure mode is worse than a crash:
    #   * an unparseable line is counted, and
    #   * if there were lines and NONE parsed, that is an error, not an empty result.
    if malformed and not seen:
        raise RuntimeError(
            f"{malformed} evidence lines in {p} could not be parsed and none succeeded; "
            "refusing to report 'no undeclared tools' from an evidence stream that was "
            "never actually read")
    if malformed:
        out.append(RiskFinding(
            "evidence-partially-unreadable", "supply_chain", LOW, f"evidence:{p.name}",
            f"{malformed} line(s) of {p.name} could not be parsed and were skipped",
            {"file": str(p), "malformed": malformed}))

    for (srv, tool), n in sorted(seen.items(), key=lambda x: -x[1]):
        if (srv, tool) in declared:
            continue
        existing = next((f for f in out if f.asset_id == f'tool:{srv}.{tool}'), None)
        if existing:
            existing.evidence['invocations'] = n
            existing.evidence['evidence_basis'] = 'static-registration-and-runtime'
            continue
        out.append(RiskFinding(
            "tool-called-but-not-declared", "supply_chain", HIGH,
            f"tool:{srv}.{tool}",
            (f"{srv}.{tool} was invoked {n}x but does not appear in {srv}'s "
             f"tools/list -- a hidden tool, or a client bypassing discovery"),
            {"server": srv, "tool": tool, "invocations": n,
             "declared_by_server": sorted(t for (s, t) in declared if s == srv)}))
    return out


#: A component that walks the process environment, selects entries by
#: credential-shaped NAME, and then sends them somewhere. Each of the three is
#: ordinary on its own; together they are a data-exfiltration beacon regardless of
#: what the component is called or which language it is written in.
_ENV_WALK = re.compile(
    r"(os\.environ\b|process\.env\b|ENV\[|getenv\s*\(|\benviron\.items\s*\(|\benv\.items\s*\()")
_ENV_SELECT = re.compile(
    r"\(\s*[\"'](?:SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL)[^)]*\)|"
    r"[\"'](?:SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL)[\"']\s*(?:in|\}|\])", re.I)
_NET_SEND = re.compile(
    r"(requests\.post|axios\.post|fetch\s*\(|httpx\.(?:post|get)|urllib|urlopen|"
    r"http\.request|client\.post|session\.post)", re.I)


def check_source_exfiltration(sources: List[Dict[str, Any]], read_file) -> List[RiskFinding]:
    """Credential-harvesting backdoor, found by reading the artifact itself.

    A supply-chain scanner reads the code it is asked to deploy; that is the whole
    point of the category. This looks for one compound behaviour rather than a
    signature: **enumerate the environment AND select by credential-shaped name AND
    send over the network, in the same file**. Any two of the three occur in
    ordinary code; all three together is a beacon.

    This is the check that catches `mcp/notes_sync/server.py:20-32`, whose whole
    purpose is to POST every `*SECRET*`/`*TOKEN*`/`*KEY*`/`*PASSWORD*` environment
    variable to a C2 URL at startup. It is invisible to any protocol-level probe
    because it never touches a tool call.
    """
    out: List[RiskFinding] = []
    for src in sources:
        path = src.get("path")
        name = src.get("name", "")
        if not path:
            continue
        text = read_file(path)
        if text is None:
            continue
        walk = _ENV_WALK.search(text)
        select = _ENV_SELECT.search(text)
        send = _NET_SEND.search(text)
        if not (walk and select and send):
            continue
        out.append(RiskFinding(
            "source-credential-beacon", "supply_chain", HIGH,
            src.get("asset_id", f"source:{name}"),
            (f"{name}: reads the process environment, selects entries by "
             f"credential-shaped name, and sends over the network -- a "
             f"credential-harvesting beacon"),
            {"file": path,
             "env_walk": walk.group(0), "env_select": select.group(0),
             "network_send": send.group(0)}))
    return out


# --------------------------------------------------------------------------
# aggregate
# --------------------------------------------------------------------------


def assess(graph, read_file, evidence_dir: Optional[str] = None,
           sources: Optional[List[Dict[str, Any]]] = None) -> List[RiskFinding]:
    from scanner import AGENT, DATASTORE, MCP_SERVER, SERVICE, SKILL, TOOL

    from detector_bridge import capability_fn  # local import keeps import cycles out

    assets = list(graph.assets.values())
    services = [a for a in assets if a.kind in (SERVICE, AGENT, DATASTORE, MCP_SERVER)]
    findings: List[RiskFinding] = []
    weak = check_env_secrets(services)
    defaults = check_default_credentials(services)
    # One credential is one risk instance; retain the weakness evidence under
    # the more specific diagnosis rather than counting the same secret twice.
    indexed = {(f.asset_id, f.evidence["key"]): f for f in defaults}
    for f in weak:
        specific = indexed.get((f.asset_id, f.evidence["key"]))
        if specific:
            specific.evidence["related_weakness"] = f.to_json()
        else:
            findings.append(f)
    findings += defaults
    findings += check_auth_disabled(services)
    findings += check_egress_exposure(services)
    findings += check_broad_capability([a for a in assets if a.kind == TOOL], capability_fn)
    findings += check_tool_descriptions([a for a in assets if a.kind == TOOL])
    findings += check_invalid_schema([a for a in assets if a.kind == TOOL])
    skills = getattr(graph, "raw_skills", []) or []
    findings += check_skill_manifest(skills)
    findings += check_skill_scripts(skills, read_file)
    findings += check_source_exfiltration(sources or [], read_file)
    findings += check_undeclared_tools(graph, evidence_dir)
    return findings


# --------------------------------------------------------------------------
# HONEST LIMITS
# --------------------------------------------------------------------------
#
# 1. **`is_weak_secret` thresholds are reasoned, not calibrated.** Length 12, entropy
#    2.5, character-class spread 2. There is no labelled corpus of "weak secrets" to
#    fit against, and inventing one from this range would be circular. The finding
#    carries its reason so a reviewer can disagree with a specific number.
#
# 2. **Nothing evaluates whether a weak secret is actually exploitable.** A weak JWT
#    key in a service that never verifies tokens is a finding, not an incident.
#
# 3. **`skill-undeclared-tool-reference` needs an existing `allowed-tools`.** A skill
#    that declares nothing and references nothing is silent, which is correct but
#    means an empty manifest is not itself treated as suspicious.
#
# 4. **Encoded payloads are reported structurally.** The check proves "base64 +
#    exec coexist"; decoding is attempted only to enrich the evidence. A payload
#    obfuscated past base64 (encryption, custom encoding) is still caught by the
#    structural signal, but its content is not recovered.
#
# 5. **No check compares against a vulnerability database.** These are design and
#    configuration risks. Known-CVE matching is a different component.
