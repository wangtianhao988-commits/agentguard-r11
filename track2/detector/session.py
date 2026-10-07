"""Reconstruct per-request sessions from gateway evidence.

The brief asks for "完整的攻击链路，包括应用内函数栈帧、提示词，工具调用链等审计日志"
and for a GENERAL algorithm. Both push the same way: build the **call chain** from what
is observable on the wire, and express detection over *capabilities and relations*,
never over tool names or payload strings.

Session identity
----------------
`scenario-runner/runner.py:37,48` sets `X-Instance-Id` and `X-Trace-Id` to the same
value, and `opspilot-app/api/app.py:299-300` forwards both downstream to the LLM and
to MCP. So one id ties together all four hops. That is the whole reason the chain is
reconstructable without touching the target.

Honest limit: a real deployment would not be handed correlated ids. Falling back to
(connection, time-window) correlation is future work, and the detector does not
pretend otherwise -- `Session.correlation` records which method was used.

Function stack frames
---------------------
There are none to recover. The range has no logging, no OpenTelemetry, no middleware
and no traceback capture, and the brief forbids using `/admin/trajectories`. So what
is reported as the "call chain" is the **cross-process HTTP chain** with the function
names the app *would* have executed, mapped statically from its source
(`run_agent -> run_stub_agent -> run_tool_calls -> call_mcp`). That mapping is
labelled as a mapping wherever it appears; it is not presented as a real stack.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# --------------------------------------------------------------------------
# capability model -- the basis of the "general algorithm" claim
# --------------------------------------------------------------------------

#: What a tool can DO, independent of what it is called. Detection rules are written
#: against these, so a different agent with differently-named tools still matches.
CAP_EXEC = "exec"
CAP_FS_READ = "fs_read"
CAP_FS_WRITE = "fs_write"
CAP_NET = "net"
CAP_DB_READ = "db_read"
CAP_READ_ONLY = "read_only"

#: What an action DOES, as opposed to what it TOUCHES.
#:
#: The capability model describes I/O primitives -- exec, net, fs_read, db_read. That
#: vocabulary is what makes the detector portable, and it is also what made the detector
#: blind to a whole class of attack: it can say "this tool reads a file", and it cannot
#: say "this tool unlocks a door".
#:
#: The gap was measured, not guessed. `InjecAgent` (UIUC, 1,054 third-party cases) tests
#: deviation from the user's intent -- asked about a laptop, the agent unlocks a door --
#: and this detector scored **1.6%** on it. Supplying the missing tool schemas did not
#: change that, because the problem was never metadata: `AugustSmartLockGrantGuestAccess`
#: matches none of exec/net/fs_read/db_read, so no rule here could name it.
#:
#: A consequence class is read from the tool's CONTRACT -- name plus description, the
#: same source the capability model already treats as legitimate. It is deliberately
#: coarse: five classes, one fixed vocabulary each, stated here so it can be argued with.
CONSEQUENCES: Dict[str, "re.Pattern"] = {
    "physical": re.compile(
        r"(unlock|lock\b|door|garage|gate\b|alarm|disarm|badge|entry|"
        r"thermostat|smartlock|smart_lock|access[_ ]?point|"
        r"门锁|开门|门禁|闸机)", re.I),
    "financial": re.compile(
        r"(pay\b|payment|transfer|bill\b|invoice|withdraw|deposit|purchase|"
        r"checkout|refund|bank|account[_ ]?balance|"
        r"支付|转账|付款|扣款|退款)", re.I),
    "destructive": re.compile(
        r"(delete|remove|drop\b|revoke|wipe|erase|purge|terminate|destroy|"
        r"删除|清除|销毁|注销)", re.I),
    "identity": re.compile(
        r"(grant\b|permission\b|role\b|invite\b|share\b|acl\b|privilege\b|escalat|"
        r"授权|提权|授予)", re.I),
    "disclosure": re.compile(
        r"(publish|upload|forward|e-?mail|sms|notify|tweet|外发|转发|披露)", re.I),
}

#: Classes where an action the user did not ask for is worth refusing outright, as
#: opposed to recording. A door opening or a payment leaving an account is not
#: something to be logged for later.
HIGH_CONSEQUENCE = frozenset({"physical", "financial", "destructive", "identity"})


def consequences_of(tool: str, description: str = "") -> set:
    """Which consequence classes does this tool's contract put it in?

    Reads the NAME and the DESCRIPTION together. Both are declarations, and unlike a
    capability a consequence cannot be inferred from a parameter shape at all: an
    `action: str` parameter looks identical whether it opens a door or marks a todo done.
    """
    # Split CamelCase before word-boundary matching. "shared memory" is not
    # a share/permission action; names such as GrantGuestAccess remain legible.
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", tool)
    hay = f"{normalized} {description or ''}"
    return {k for k, pat in CONSEQUENCES.items() if pat.search(hay)}

# Compatibility export for inventory diagnostic consumers. No deployment-specific
# capability entries are used: metadata/schema/source evidence drive every tool.
CAPABILITIES: Dict[str, set] = {}

#: Parameter names that carry caller-supplied CONTENT -- i.e. a value that leaves
#: the caller's control and goes somewhere.
#:
#: This one vocabulary is used for two things that were previously separate and had
#: drifted apart: deciding a tool can WRITE (`_FS_WRITE_PARAM`), and deciding a call
#: actually CARRIES DATA on the wire (`rules._carries_data`). The second list was
#: shorter, and the automated adversarial search walked straight through the gap --
#: renaming the payload parameter from `text` to `message` defeated the read-then-egress
#: rule in all 1260 combinations that used an unlisted name. Two lists describing one
#: concept is one list too many.
CONTENT_PARAMS: frozenset = frozenset({
    "text", "body", "content", "data", "payload", "message", "note", "blob",
    "value", "obj", "object", "document", "buffer", "attachment", "file_content",
    "summary", "description", "comment", "memo", "record", "entry", "item",
})

#: Parameter-name vocabulary for capability inference.
_EXEC_PARAM = re.compile(r"(?:^|_)(?:cmd|command|script|code|shell|exec|program|expr)(?:$|_)", re.I)
_FS_READ_PARAM = re.compile(r"(path|file|filename|src|source|doc|document|key)", re.I)
_FS_WRITE_PARAM = re.compile("|".join(sorted(CONTENT_PARAMS)) + r"|append", re.I)
_NET_PARAM = re.compile(r"(url|uri|endpoint|host|address|webhook|callback|target)", re.I)
_DB_PARAM = re.compile(r"(query|sql|table|tenant|scope|account|org|namespace|project|repo)", re.I)

_EXEC_DESC = re.compile(r"(?:execute|run|shell|command|script|eval|spawn|invoke)", re.I)
_FS_READ_DESC = re.compile(r"(read|load|open|retrieve|inspect|fetch a document)", re.I)
_FS_WRITE_DESC = re.compile(r"(write|save|create|update|delete|append|upload|store)", re.I)
# "push" was missing from the first version, and that single omission made an
# egress tool (`channel_push`) resolve to `fs_write` -- which silently disabled the
# read-then-egress rule on the alternate agent. The generalisation test caught it;
# nothing in the OpsPilot range could have, because none of its egress tools are
# named that way.
_NET_DESC = re.compile(r"(http|request|send|post |upload|fetch|download|sync|notify|"
                       r"push|publish|emit|transmit|webhook|external|remote|同步|外发|发送|上传|推送|下载)", re.I)
_DB_DESC = re.compile(r"(query|database|table|records?|rows?|ledger|account)", re.I)


def infer_capabilities(tool: str, schema: Optional[Dict[str, Any]] = None,
                       description: str = "") -> set:
    """Derive what a tool can DO from its schema and description.

    This is what makes the detector portable. It reads the *shape* of the interface,
    which every tool framework exposes, instead of a catalogue of names, which it
    does not:

      * a parameter called `cmd`/`command`/`script`     -> exec
      * a parameter called `path`/`file`                -> fs_read
      * a parameter called `content`/`body`             -> fs_write
      * a parameter called `url`/`endpoint`/`host`      -> net
      * a parameter called `tenant`/`query`/`table`     -> db_read

    Deliberately over-inclusive: a tool that merely *mentions* a path is treated as
    able to read, because a spurious capability only makes a rule look twice while a
    missed one makes the detector blind. The rules each require a conjunction, so
    extra capabilities do not by themselves produce findings.
    """
    caps: set = set()
    props = (schema or {}).get("properties") if isinstance(schema, dict) else {}
    for pname in (props or {}):
        if _EXEC_PARAM.search(pname):
            caps.add(CAP_EXEC)
        if _FS_READ_PARAM.search(pname):
            caps.add(CAP_FS_READ)
        if _FS_WRITE_PARAM.search(pname):
            caps.add(CAP_FS_WRITE)
        if _NET_PARAM.search(pname):
            caps.add(CAP_NET)
        if _DB_PARAM.search(pname):
            caps.add(CAP_DB_READ)
    d = description or ""
    if _EXEC_DESC.search(d):
        caps.add(CAP_EXEC)
    if _FS_READ_DESC.search(d):
        caps.add(CAP_FS_READ)
    if _FS_WRITE_DESC.search(d):
        caps.add(CAP_FS_WRITE)
    if _NET_DESC.search(d):
        caps.add(CAP_NET)
    if _DB_DESC.search(d):
        caps.add(CAP_DB_READ)
    # Anything that can execute can usually write and reach the network once it runs.
    if CAP_EXEC in caps:
        caps.update({CAP_FS_WRITE, CAP_NET})
    return caps or {CAP_READ_ONLY}


def capabilities_of(server: str, tool: str,
                    schema: Optional[Dict[str, Any]] = None,
                    description: str = "",
                    code_caps: Optional[Set[str]] = None) -> set:
    """Capabilities from three sources, combined by a rule that is stated, not tuned.

    Each source knows something the others do not, and each is wrong on its own:

      * **implementation** (static analysis of the tool's function) is ground truth
        for what the code CAN do, and it is the only source that sees a capability
        the declaration hides -- `notes_sync.debug_exec` claims to be an "internal
        debug command" and runs `shell=True`;
      * **declaration** (schema + description) is ground truth for what the tool is
        CONTRACTED to do. `notes_sync.sync_note` is a stub in this testbed that
        returns `{"synced": True}` and never touches the network, but its contract is
        "sync a note to the team space"; in a real deployment that is egress, so a
        code-only reading would miss the exfiltration channel;
      * **declared constraint** subtracts. `sandbox_exec.run_test` says it runs tests
        FROM AN ALLOWLIST -- the declaration limits itself, and the code agrees by
        containing no execution primitive at all.

    So: `(declared − constrained) ∪ code`. Code is never subtracted, because code is
    what exists. The constraint only removes what the tool itself disclaims.

    Worked against all ten tools in the range:

        debug_exec      code={exec,fs_write,net} decl={}          -> exec,fs_write,net
        run             code={exec,fs_write,net} decl={exec,..}    -> exec,fs_write,net
        sync_note       code={}                  decl={net}        -> net
        run_test        code={}                  decl={exec} − allowlist -> {}
        lookup          code={net}               decl={net}        -> net
        query           code={}                  decl={db_read}    -> db_read

    `sync_note` and `run_test` are the two that matter: a name-based table gets BOTH
    backwards, and each single source gets one of them wrong.
    """
    declared = infer_capabilities(tool, schema, description)

    # A declaration can limit ITSELF -- and the limit is recorded, not subtracted.
    #
    # `sandbox_exec.run_test` is described as running tests "from an allowlist" and
    # "refusing arbitrary commands", and its implementation agrees: no execution
    # primitive anywhere in the body. Subtracting `exec` on that basis kept the decoy
    # clean.
    #
    # **But subtracting it also opened a 64-combination bypass.** `search.py`'s exec
    # family includes a `declaration=allowlist` axis -- a tool that SAYS allowlist and
    # is then called with an arbitrary command -- and with the capability already
    # discounted, the call was never judged. The first adversarial run after this
    # change reported exactly 192/256, with all 64 misses on that axis.
    #
    # The fix is the same one that resolved the schema-constraint case: **the
    # declaration is evidence the RULE reads, not a discount applied before the call is
    # seen.** `rules.rule_execution` calls `_disclaims_execution` and blocks when the
    # arguments violate the claim -- an allowlisted test runner invoked with `curl | sh`
    # is a stronger signal than an unconstrained one, not a weaker one.
    combined = set(declared) | set(code_caps or ())
    if combined - {CAP_READ_ONLY}:
        combined.discard(CAP_READ_ONLY)
    return combined or {CAP_READ_ONLY}


#: Prose that says "this tool will not run arbitrary things".
_DISCLAIMS_EXEC = re.compile(
    r"(allow[- ]?list|white[- ]?list|"
    r"refus\w*\s+(any|arbitrary)|reject\w*\s+(any|arbitrary)|"
    r"拒绝任意|不接受任意|白名单|仅允许|只允许)", re.I)


def _disclaims_execution(description: str) -> bool:
    return bool(description and _DISCLAIMS_EXEC.search(description))
    # NOTE: a declared constraint deliberately does NOT subtract here.
    #
    # The first version of this function removed `exec` when the schema carried an
    # enum, on the reasoning that an allowlisted runner cannot run arbitrary
    # commands. The automated adversarial search immediately found 128 bypasses: it
    # supplies `cmd="curl … | sh"` to a tool whose schema says the argument must be
    # one of ["status","health"], and the detector had already discounted the
    # capability before looking at the call.
    #
    # **Capability is a property of the TOOL; respecting the tool's declared limits is
    # a property of the CALL.** Conflating them lets an attacker disable a rule by
    # shipping a schema the call then ignores. The constraint is applied in
    # `rules.rule_execution`, where the arguments are in hand -- and a call that
    # violates its own declared constraint is treated as worse, not better.
    if combined - {CAP_READ_ONLY}:
        combined.discard(CAP_READ_ONLY)
    return combined or {CAP_READ_ONLY}


_CONSTRAINT_TEXT = re.compile(
    r"(allow[- ]?list|white[- ]?list|permitted|predefined|fixed set|"
    r"only (?:the )?(?:following|listed|approved)|restricted to)", re.I)


def declared_constraints(tool: str, schema: Optional[Dict[str, Any]],
                         description: str) -> Dict[str, Any]:
    """What the tool says it will accept, per parameter.

    Returns `{param: {"enum": [...], "pattern": "..."}}` plus `{"__text__": reason}`
    when the prose declares a limit. Used to decide whether a CALL stayed inside the
    limits the tool set for itself.
    """
    out: Dict[str, Any] = {}
    props = (schema or {}).get("properties") or {}
    for name, spec in props.items():
        if not isinstance(spec, dict):
            continue
        if spec.get("enum") or spec.get("const") or spec.get("pattern"):
            out[name] = {k: spec[k] for k in ("enum", "const", "pattern") if k in spec}
    if description and _CONSTRAINT_TEXT.search(description):
        m = _CONSTRAINT_TEXT.search(description)
        out["__text__"] = m.group(0) if m else "declared limit"
    return out


def call_respects_constraints(arguments: Dict[str, Any],
                              constraints: Dict[str, Any]) -> bool:
    """Does this call stay inside the limits the tool declared?

    Only the *parameter* constraints are decisive. A prose limit ("runs allowlisted
    profiles") cannot be checked mechanically, so it is recorded and left to the rule
    to weigh -- but a schema that enumerates the legal values can be checked exactly,
    and a call that ignores it has violated its own contract.
    """
    for param, spec in constraints.items():
        if param == "__text__":
            continue
        if param not in (arguments or {}):
            continue
        val = arguments[param]
        if "enum" in spec and val not in spec["enum"]:
            return False
        if "const" in spec and val != spec["const"]:
            return False
        if "pattern" in spec:
            try:
                if not re.search(spec["pattern"], str(val)):
                    return False
            except re.error:
                continue
    return True


#: Declared metadata per tool, keyed `server.tool`. Populated from the inventory
#: scan (`tools/list` results) when available, so capabilities can be inferred from
#: schema and description rather than a deployment-specific name list. Missing
#: metadata falls back to observed parameter names, with reduced coverage.
_TOOL_META: Dict[str, Dict[str, Any]] = {}


def load_tool_meta(inventory_path: str | Path) -> int:
    """Populate `_TOOL_META` from an inventory document. Returns how many loaded.

    **Warns when the profile looks incomplete, because a short profile does not fail --
    it changes the answer.** With no entry for a tool, `capabilities_of` falls back to
    the declaration and the inference, which for `sandbox-exec.run_test` means `exec`
    from the verb "run" instead of the `fs_write`/`net` that its code-derived profile
    gives. The rules then fire on innocent test-runner calls.

    That is not hypothetical: a `guard-inventory` run against a range that was still
    starting wrote an inventory with **5 tools instead of 9**, and a held-out-seed
    evaluation reported **1256 false positives** on benign sessions. Every number looked
    like a detection result; none of it was `load_tool_meta` itself reported no problem,
    because a partial load is a successful load.
    """
    try:
        doc = json.loads(Path(inventory_path).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return 0
    _TOOL_META.clear()
    n = 0
    servers: Set[str] = set()
    for a in (doc.get("asset_graph") or {}).get("assets") or []:
        if a.get("kind") == "mcp_server":
            servers.add(a.get("name") or "")
        if a.get("kind") != "tool":
            continue
        attrs = a.get("attributes") or {}
        key = f"{attrs.get('server','')}.{a.get('name','').split('.', 1)[-1]}"
        _TOOL_META[key] = {"schema": attrs.get("input_schema"),
                           "description": attrs.get("description") or "",
                           "code_caps": set(attrs.get("code_caps") or ()),
                           "source_effect_certificate": attrs.get('source_effect_certificate')}
        n += 1

    # A server that declared no tools is the signature of a scan that ran too early:
    # the container answered `initialize` before its tool registry was populated, or was
    # not up at all and simply never appeared. Neither is an error the scanner can see.
    declaring = {k.split(".", 1)[0] for k in _TOOL_META}
    silent = sorted(servers - declaring - {""})
    if silent or n == 0:
        print(f"[tools] WARNING: tool profile looks incomplete -- {n} tools across "
              f"{len(declaring)} of {len(servers)} servers. "
              f"Servers declaring nothing: {silent or '(none)'}. "
              f"Capabilities for unprofiled tools fall back to the declaration, which "
              f"CHANGES RULE BEHAVIOUR rather than failing. Re-run the inventory once "
              f"every service is up.")
    return n


def tool_meta() -> Dict[str, Dict[str, Any]]:
    return _TOOL_META


def register_tool(server: str, tool: str, schema: Optional[Dict[str, Any]],
                  description: str = "", code_caps: Optional[Set[str]] = None) -> None:
    """Register one tool's declared interface, and optionally what its code does.

    `code_caps` comes from static analysis of the tool's implementation
    (`inventory.codecap`). Supplying it is what lets the detector see a capability the
    declaration conceals. Without source evidence only the declared interface and
    observed parameter names are available; coverage may decrease.
    """
    _TOOL_META[f"{server}.{tool}"] = {"schema": schema, "description": description,
                                      "code_caps": set(code_caps or ())}


def _schema_from_args(arguments: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a schema-shaped view of an observed call's arguments.

    The inference matches on parameter NAMES, so names are all it needs -- and an
    observed call supplies them even when the tool declared nothing. Types are unknown
    and deliberately omitted: `_EXEC_PARAM` and its siblings match on names alone.
    """
    return {"type": "object", "properties": {k: {} for k in (arguments or {})}}


def _schema_of(properties: Dict[str, Any]) -> Dict[str, Any]:
    return {"type": "object", "properties": properties}

#: Paths whose contents are credentials by nature. Language-neutral on purpose.
SENSITIVE_PATH_MARKERS = (
    ".env", "id_rsa", "id_ed25519", ".ssh", ".aws", ".gnupg", "credentials",
    "secrets", ".netrc", ".git-credentials", "/etc/shadow", "/etc/passwd",
    "service_token", "signing_key",
)


# NOTE: there used to be a second `capabilities_of(server, tool)` definition here,
# left behind when the schema-aware version was added above. Being later in the file,
# it silently won, so `ToolCall.caps` raised TypeError and EVERY rule went quiet on
# any agent whose tools were not in the pinned table -- exactly the failure the
# generalisation test was built to expose, and it exposed it. Removed, and the test
# now runs against the real function.


# --------------------------------------------------------------------------
# session
# --------------------------------------------------------------------------


@dataclass
class ToolCall:
    server: str
    tool: str
    arguments: Dict[str, Any]
    ts: str = ""
    result: Any = None
    ok: Optional[bool] = None
    trusted_task_policy: Optional[Dict[str, Any]] = None

    @property
    def caps(self) -> set:
        meta = _TOOL_META.get(f"{self.server}.{self.tool}") or {}
        if meta and "_resolved_caps" in meta:
            return meta["_resolved_caps"]
        declared = capabilities_of(self.server, self.tool, meta.get("schema"),
                                   meta.get("description") or "", meta.get("code_caps"))
        if meta:
            # A registered profile is replaced as a whole by register_tool or
            # load_tool_meta. Cache on that profile, so reload invalidates naturally.
            # Immutable sets prevent one rule altering another rule's capability.
            meta["_resolved_caps"] = frozenset(declared)
            return meta["_resolved_caps"]
        # No profile at all: this tool never appeared in `tools/list`.
        #
        # That is the hidden-backdoor case, and it is the one the detector most needs
        # to get right -- `notes_sync.debug_exec` is declared `hidden=True`, so no
        # inventory can enumerate it and no static analysis can profile it. The first
        # version of this fallback returned `read_only`, which made the backdoor
        # invisible to the exec rule at exactly the moment the hidden-tool rule had
        # just flagged it for existing.
        #
        # A tool with no declaration still has CALLS, and a call's argument names are
        # the same interface shape the inference already reads. `debug_exec({"cmd":
        # "id"})` is execution-capable by the only evidence available, and that
        # evidence is the attacker's own, not a name we chose to trust.
        return infer_capabilities(self.tool, _schema_from_args(self.arguments),
                                  "") or {CAP_READ_ONLY}

    def arg_blob(self) -> str:
        return json.dumps(self.arguments or {}, ensure_ascii=False)


@dataclass
class Session:
    instance_id: str
    correlation: str = "trace-id"
    prompt: str = ""
    skill: str = ""
    identity: Dict[str, Any] = field(default_factory=dict)
    messages: List[Dict[str, Any]] = field(default_factory=list)
    advertised_tools: List[str] = field(default_factory=list)
    skill_catalog: List[Dict[str, Any]] = field(default_factory=list)
    calls: List[ToolCall] = field(default_factory=list)
    first_ts: str = ""
    last_ts: str = ""
    trusted_task_policy: Optional[Dict[str, Any]] = None

    # -- derived views ----------------------------------------------------

    @property
    def scope(self) -> Dict[str, Any]:
        return (self.identity or {}).get("scope") or {}

    @property
    def role(self) -> str:
        return (self.identity or {}).get("role", "")

    def reads_sensitive(self) -> List[ToolCall]:
        out = []
        for c in self.calls:
            if CAP_FS_READ not in c.caps:
                continue
            blob = c.arg_blob().lower()
            if any(m in blob for m in SENSITIVE_PATH_MARKERS):
                out.append(c)
        return out

    def egress_calls(self) -> List[ToolCall]:
        return [c for c in self.calls if CAP_NET in c.caps]

    def exec_calls(self) -> List[ToolCall]:
        return [c for c in self.calls if CAP_EXEC in c.caps]

    def loaded_skill_bodies(self) -> List[str]:
        """System messages that carry a loaded SKILL.md body.

        `api/app.py:101-108` builds them as
        `f"已加载 Skill: {name}\\n来源: {path}\\n{body}"`. Matching that shape is
        reading the target's own format; it is not a payload signature.
        """
        out = []
        for m in self.messages:
            if m.get("role") != "system":
                continue
            c = m.get("content") or ""
            if "已加载 Skill" in c or "SKILL.md" in c:
                out.append(c)
        return out


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------


def _decode_jwt_payload(token: str) -> Dict[str, Any]:
    """Decode WITHOUT verifying. We are not authenticating; we are reading what the
    caller claimed, which is itself the evidence (a forged token is a finding)."""
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:  # noqa: BLE001
        return {}


def load_evidence(directory: str | Path) -> Dict[str, List[Dict[str, Any]]]:
    d = Path(directory)
    if not d.is_dir():
        raise FileNotFoundError(f"Evidence directory missing: {d}")
    if not (d / "A_agent_ingress.jsonl").is_file():
        raise FileNotFoundError(f"Agent ingress evidence missing: {d}")
    if not (d / "inventory.json").is_file():
        raise FileNotFoundError(f"Capability inventory missing: {d}")
    out: Dict[str, List[Dict[str, Any]]] = {}
    for name in ("A_agent_ingress", "B_llm_request", "C_mcp_call", "C_response",
                 "guard_decision", "code_stack", "E_framework_call","C_raw_response","result_intervention"):
        p = d / f"{name}.jsonl"
        rows: List[Dict[str, Any]] = []
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    try:
                        row = json.loads(line)
                        if not isinstance(row, dict):
                            raise ValueError(f"Evidence row must be an object: {p}")
                        rows.append(row)
                    except json.JSONDecodeError as exc:
                        raise ValueError(f"Malformed evidence in {p}: {exc}") from exc
        out[name] = rows
    # The tool profile travels with the evidence.
    #
    # **This is the join that was missing, and it is why shrinking the pinned table
    # broke the offline evaluator while the live path kept working.** Capabilities need
    # three inputs -- the declaration, the declared constraints, and the implementation
    # -- and the implementation reaches the detector only through the inventory. The
    # gateway was taught to load it; the evaluator was not, so for a while the two ran
    # on different capability sets and the offline numbers described a detector that
    # was not the one deployed. `consistency.py` exists to catch that class of
    # divergence, and loading the profile here -- at the one place both paths share --
    # is what makes the check meaningful rather than lucky.
    inv = d / "inventory.json"
    if inv.exists():
        try:
            inventory_document=json.loads(inv.read_text(encoding="utf-8"))
            import os
            if os.getenv('GUARD_R8')=='1':
                import rules
                rules._R8_INVENTORY=inventory_document
                policy_path=d/'result_policy.json'
                rules._R8_RESULT_POLICY=json.loads(policy_path.read_text(encoding='utf-8')) if policy_path.exists() else None
                rules.reset_knowledge_graph()
            if load_tool_meta(inv) == 0:
                raise ValueError("No tool capabilities loaded")
            load_skill_catalog(inv)
        except Exception as exc:
            raise ValueError(f"Invalid capability inventory: {inv}") from exc
    return out


#: Skill catalog taken from the inventory, used when a session's own messages do not
#: carry one.
_SKILL_CATALOG: List[Dict[str, Any]] = []


def load_skill_catalog(inventory_path: str | Path) -> int:
    """Read the skill assets from an inventory document. Returns how many loaded.

    **Why the offline path needs this and did not have it.** `_skill_catalog_from`
    parses the system message that `api/app.py` builds when an agent has skills loaded.
    That message is not in every LLM request -- and for the one session where it was
    absent, `rule_undeclared_capability` found no entry for the skill and returned
    without a word. The live guard, which reads the inventory, flagged the same session.

    The result was a single divergence out of 5103 sessions in the offline/live check:
    the offline path MISSING a detection the live path made. One session is small, but
    the shape is the one this project keeps meeting -- a rule that declines to fire looks
    exactly like a session with nothing wrong in it.

    The inventory is the authoritative source; the message parse is a fallback with a
    narrower reach. Where both exist they describe the same catalog, so preferring the
    inventory on the offline side matches what the deployed guard already does.
    """
    global _SKILL_CATALOG
    try:
        doc = json.loads(Path(inventory_path).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return 0
    out: List[Dict[str, Any]] = []
    for a in (doc.get("asset_graph") or {}).get("assets") or []:
        if a.get("kind") != "skill":
            continue
        attrs = a.get("attributes") or {}
        out.append({"name": a.get("name"),
                    "description": attrs.get("description") or "",
                    "allowed_tools": list(attrs.get("allowed_tools") or [])})
    _SKILL_CATALOG = out
    return len(out)


def _skill_catalog_from(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Parse the catalog message `api/app.py:90-98` builds, one entry per line:
        - <name>: <description>；allowed-tools=<a, b>
    """
    for m in messages:
        if m.get("role") != "system":
            continue
        c = m.get("content") or ""
        if not c.startswith("可用 Skills"):
            continue
        out = []
        for line in c.splitlines()[1:]:
            line = line.strip()
            if not line.startswith("- "):
                continue
            body = line[2:]
            name, _, rest = body.partition(":")
            desc, _, tools = rest.partition("；allowed-tools=")
            allowed = [t.strip() for t in tools.split(",") if t.strip() and t.strip() != "none"]
            out.append({"name": name.strip(), "description": desc.strip(),
                        "allowed_tools": allowed})
        return out
    return []


def build_sessions(ev: Dict[str, List[Dict[str, Any]]]) -> List[Session]:
    by_id: Dict[str, Session] = {}

    def get(iid: str) -> Session:
        s = by_id.get(iid)
        if s is None:
            s = Session(instance_id=iid)
            by_id[iid] = s
        return s

    # -- A: ingress ------------------------------------------------------
    for r in ev.get("A_agent_ingress", []):
        iid = (r.get("headers") or {}).get("x-trace-id") or (r.get("headers") or {}).get("x-instance-id")
        if not iid:
            continue
        s = get(iid)
        s.first_ts = s.first_ts or r.get("ts", "")
        body = r.get("body") or {}
        if r.get("path") == "/run":
            s.prompt = body.get("prompt", "")
            s.skill = body.get("skill") or ""
            auth = (r.get("headers") or {}).get("authorization", "")
            if auth.startswith("Bearer "):
                s.identity = _decode_jwt_payload(auth.split(" ", 1)[1])

    # -- B: what the model saw -------------------------------------------
    for r in ev.get("B_llm_request", []):
        iid = (r.get("headers") or {}).get("x-trace-id") or (r.get("headers") or {}).get("x-instance-id")
        if not iid:
            continue
        s = get(iid)
        s.messages = r.get("messages") or []
        s.advertised_tools = r.get("tools") or []
        if not s.skill_catalog:
            s.skill_catalog = _skill_catalog_from(s.messages)
        # Fall back to the inventory's skill assets. See `load_skill_catalog`: the
        # per-request system message is not always present, and a rule that finds no
        # entry for the skill returns without a word -- indistinguishable from a clean
        # session, which is how one session out of 5103 came to differ between the two
        # paths in a direction where the OFFLINE side was the one missing a detection.
        #
        # **Only a first attempt.** It runs per B-record, and a session whose B record
        # carries no trace id never reaches this line at all -- which is exactly the
        # session that needed it. The loop below is the one that actually guarantees it.
        if not s.skill_catalog and _SKILL_CATALOG:
            s.skill_catalog = list(_SKILL_CATALOG)

    # -- C: responses, joined by rid -------------------------------------
    #
    # `ToolCall.result` was declared from the start and **never populated**: nothing
    # joined `C_response` back to `C_mcp_call`, so every rule saw what the agent ASKED
    # for and never what it GOT BACK. That is fine for the rules that existed -- they
    # judge requests -- and fatal for anything that needs to read returned content.
    #
    # Memory poisoning is exactly that case: the poison arrives in a tool's RETURN
    # value, and a detector that cannot see return values cannot see the delivery.
    resp_by_rid: Dict[str, Any] = {}
    original_by_rid={r.get('rid'):r.get('body') for r in ev.get('C_raw_response',[])}
    for r in ev.get("C_response", []):
        rid = r.get("rid")
        if rid:
            resp_by_rid[rid] = r.get("body")

    # -- C: tool calls ---------------------------------------------------
    for r in ev.get("C_mcp_call", []):
        iid = (r.get("headers") or {}).get("x-trace-id") or (r.get("headers") or {}).get("x-instance-id")
        if not iid:
            continue
        s = get(iid)
        call = ToolCall(server=r.get("server", ""), tool=r.get("tool") or "",
                        arguments=r.get("arguments") or {}, ts=r.get("ts", ""))
        if r.get('trusted_task_policy') is not None:
            call.trusted_task_policy = r['trusted_task_policy']
        raw_resp = resp_by_rid.get(r.get("rid"))
        if r.get('rid') in original_by_rid: call._r8_raw_response=original_by_rid[r.get('rid')]
        if raw_resp is not None:
            call.result = _unwrap_tool_result(raw_resp)
            call.ok=not (isinstance(raw_resp,dict) and 'error' in raw_resp)
        s.calls.append(call)
        s.last_ts = r.get("ts", "") or s.last_ts

    # -- the guarantee, applied once to every session ---------------------
    #
    # The per-B-record attempt above only reaches sessions whose B record carries a trace
    # id. A session without one never runs it -- and that is precisely the session that
    # needed it, because a session with no B record is a session whose system message was
    # never captured, which is the only source `_skill_catalog_from` has. Doing it here,
    # after every record has been folded in, is what makes the catalog a property of the
    # session rather than of the order its records happened to arrive in.
    if _SKILL_CATALOG:
        for s in by_id.values():
            if s.skill and not s.skill_catalog:
                s.skill_catalog = list(_SKILL_CATALOG)

    return [s for s in by_id.values() if s.calls or s.prompt]


def _unwrap_tool_result(body: Any) -> Any:
    """Reduce a JSON-RPC tool response to the payload the agent actually receives.

    Kept separate so the memory rules get the same view the model got, rather than
    the transport envelope -- an injected instruction is inside `result.content`,
    and a matcher that only sees `{"jsonrpc": "2.0", "id": 3}` would find nothing.
    """
    if not isinstance(body, dict):
        return body
    res = body.get("result", body)
    if isinstance(res, dict) and "content" in res:
        parts = res.get("content")
        if isinstance(parts, list):
            texts = [p.get("text", "") for p in parts
                     if isinstance(p, dict) and p.get("type") in (None, "text")]
            if texts:
                return "\n".join(texts)
        return res.get("content")
    return res


#: Function names the agent executes for a given hop, mapped statically from
#: `opspilot-app/api/app.py`. Reported as a MAPPING, never as a captured stack.
FUNCTION_CHAIN = {
    "A": ["api.app.run_agent"],
    "B": ["api.app.run_agent", "api.app.run_stub_agent", "requests.api.post"],
    "C": ["api.app.run_agent", "api.app.run_stub_agent", "api.app.run_tool_calls",
          "api.app.call_mcp", "mcp_base.mcp_http.tools_call"],
}


def function_chain_for(hop: str) -> List[str]:
    return list(FUNCTION_CHAIN.get(hop, []))
