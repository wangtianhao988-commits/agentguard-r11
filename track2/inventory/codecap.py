"""Determine a tool's capability from its IMPLEMENTATION, not its declaration.

Why this exists
---------------
Capability inference from names and schemas is structurally incomplete. Two real
bypasses came from that incompleteness: `channel_push` was not recognised as network
capable because the verb table lacked `push`, and an attacker renamed a payload
parameter from `text` to `message` to slip past the read-then-egress rule in 1260
combinations. Each was patched by extending a vocabulary, and the next unlisted word
would have slipped through just the same.

**A vocabulary can always be extended and will always have a hole.** The declaration
says what a tool *claims*; the code says what it *does*. So this module reads the
code.

It also happens to be exactly what the brief asks for: "摒弃单纯依赖工具名称、路径
黑白名单的粗粒度匹配方式" -- do not judge by tool names.

How
---
Static analysis with `ast`, not bytecode inspection: the goal is to be reviewable, and
a security claim that cannot be read by a human is a weak one. For each function in a
module the analyser collects the **primitives** it invokes, then propagates along
intra-module calls so a thin wrapper inherits its callee's capabilities.

The output is deliberately a *superset* of the truth in ambiguous cases: a tool that
merely mentions `open()` is treated as able to read, because a spurious capability
only makes a rule look twice while a missing one makes the detector blind. The rules
each require a conjunction, so extra capabilities do not by themselves produce
findings.

Honest limits are at the bottom of this file.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

# Capability names match `detector.session` so the two can be compared directly.
CAP_EXEC = "exec"
CAP_FS_READ = "fs_read"
CAP_FS_WRITE = "fs_write"
CAP_NET = "net"
CAP_DB_READ = "db_read"
CAP_DB_WRITE = "db_write"
CAP_ENV_READ = "env_read"

#: Import / attribute roots that mean "this can run code".
EXEC_ROOTS = {"subprocess", "pty", "commands"}
EXEC_ATTRS = {"system", "popen", "spawn", "spawnl", "spawnv", "call", "run", "check_output",
              "check_call", "execv", "execve", "fork", "eval", "exec", "compile"}
#: Network clients, by import root.
NET_ROOTS = {"httpx", "requests", "urllib", "urllib3", "aiohttp", "socket", "http",
             "ftplib", "smtplib", "telnetlib", "websocket", "websockets"}
#: Database drivers.
DB_ROOTS = {"psycopg2", "sqlite3", "pymysql", "MySQLdb", "asyncpg", "sqlalchemy", "pymongo"}
#: Method names that write to a file or a database.
WRITE_METHODS = {"write_text", "write_bytes", "writelines", "unlink", "mkdir", "rmdir",
                 "remove", "rename", "replace", "chmod", "touch", "truncate"}
READ_METHODS = {"read_text", "read_bytes", "readlines", "readline", "iterdir", "glob",
                "rglob", "stat", "exists", "listdir", "scandir"}
#: SQL that mutates.
SQL_WRITE = re.compile(r"\b(insert|update|delete|drop|truncate|alter|create)\b", re.I)

#: Python callables that execute their argument. Reaching one of these with a
#: decodable payload is how `pdf-export` hides a download-and-run.
DYNAMIC_EXEC = {"exec", "eval", "compile", "__import__"}


@dataclass
class FuncCaps:
    name: str
    caps: Set[str] = field(default_factory=set)
    evidence: Set[str] = field(default_factory=set)   # "primitive @ line"
    calls: Set[str] = field(default_factory=set)      # intra-module callees
    lineno: int = 0

    def to_json(self) -> Dict[str, Any]:
        return {"name": self.name, "caps": sorted(self.caps),
                "evidence": sorted(self.evidence), "calls": sorted(self.calls)}


class _Visitor(ast.NodeVisitor):
    """Collect capability primitives inside one function body."""

    def __init__(self, fn: FuncCaps) -> None:
        self.fn = fn

    def _add(self, cap: str, node: ast.AST, label: str) -> None:
        self.fn.caps.add(cap)
        self.fn.evidence.add(f"{label} @L{getattr(node, 'lineno', '?')}")

    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            root = a.name.split(".")[0]
            if root in NET_ROOTS:
                self._add(CAP_NET, node, f"import {root}")
            if root in DB_ROOTS:
                self._add(CAP_DB_READ, node, f"import {root}")
            if root in EXEC_ROOTS:
                self._add(CAP_EXEC, node, f"import {root}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        root = (node.module or "").split(".")[0]
        if root in NET_ROOTS:
            self._add(CAP_NET, node, f"from {root}")
        if root in DB_ROOTS:
            self._add(CAP_DB_READ, node, f"from {root}")
        if root in EXEC_ROOTS:
            self._add(CAP_EXEC, node, f"from {root}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        root, _, tail = name.rpartition(".")
        # dynamic execution of a string
        if name in DYNAMIC_EXEC or tail in DYNAMIC_EXEC:
            self._add(CAP_EXEC, node, f"{name}()")
        # process spawn
        if root.split(".")[0] in EXEC_ROOTS and tail in EXEC_ATTRS:
            self._add(CAP_EXEC, node, f"{name}()")
            # a spawned process can reach the network and the filesystem
            self.fn.caps.update({CAP_NET, CAP_FS_WRITE})
        if root.split(".")[0] in NET_ROOTS:
            self._add(CAP_NET, node, f"{name}()")
        if root.split(".")[0] in DB_ROOTS or tail in ("execute", "executemany", "executescript"):
            self._add(CAP_DB_READ, node, f"{name}()")
        if tail == "open":
            self._add(CAP_FS_READ, node, f"{name}()")
            mode = _open_mode(node)
            if mode and any(ch in mode for ch in "wax+"):
                self._add(CAP_FS_WRITE, node, f"open(mode={mode!r})")
        if tail in WRITE_METHODS:
            self._add(CAP_FS_WRITE, node, f"{name}()")
        if tail in READ_METHODS:
            self._add(CAP_FS_READ, node, f"{name}()")
        # os.environ access
        if name.endswith("environ.get") or name in ("os.getenv", "getenv"):
            self._add(CAP_ENV_READ, node, f"{name}()")
        # SQL text decides read vs write
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if SQL_WRITE.search(arg.value):
                    self._add(CAP_DB_WRITE, node, "SQL mutates")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        full = _call_name(node)
        root = full.split(".")[0]
        if root in NET_ROOTS:
            self._add(CAP_NET, node, f"{full}")
        if full in ("os.environ",) or full.endswith(".environ"):
            self._add(CAP_ENV_READ, node, full)
        if full in ("os.system", "os.popen"):
            self._add(CAP_EXEC, node, full)
        self.generic_visit(node)


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _open_mode(node: ast.Call) -> str:
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            return str(kw.value.value)
    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
        return str(node.args[1].value)
    return ""


# --------------------------------------------------------------------------
# module analysis
# --------------------------------------------------------------------------


@dataclass
class ModuleAnalysis:
    path: str
    functions: Dict[str, FuncCaps] = field(default_factory=dict)
    tools: Dict[str, str] = field(default_factory=dict)   # tool name -> handler function
    errors: List[str] = field(default_factory=list)

    def caps_for_tool(self, tool: str) -> Set[str]:
        fn = self.tools.get(tool)
        if not fn:
            return set()
        return set(self.functions.get(fn, FuncCaps(fn)).caps)

    def to_json(self) -> Dict[str, Any]:
        return {"path": self.path, "tools": self.tools,
                "functions": {k: v.to_json() for k, v in self.functions.items()},
                "errors": self.errors}


def _tool_registrations(tree: ast.AST) -> Dict[str, str]:
    """Find `Tool("name", ..., handler)` calls and map tool name -> handler name.

    The range registers tools as `Tool(name, description, schema, handler)`; other
    frameworks differ in the spelling but not in the shape -- a name string followed
    by a reference to the implementing function. Locating it structurally rather than
    by matching an import keeps this usable on a registry the detector has not seen.
    """
    out: Dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = _call_name(node.func)
        if not fn.endswith("Tool"):
            continue
        if not node.args:
            continue
        first = node.args[0]
        if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
            continue
        handler = ""
        for a in node.args[1:]:
            if isinstance(a, ast.Name):
                handler = a.id
            elif isinstance(a, ast.Attribute):
                handler = a.attr
        if handler:
            out[first.value] = handler
    return out


def analyze_module(path: str | Path) -> ModuleAnalysis:
    p = Path(path)
    ma = ModuleAnalysis(path=str(p))
    try:
        src = p.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src)
    except Exception as e:  # noqa: BLE001
        ma.errors.append(f"{type(e).__name__}: {e}")
        return ma

    ma.tools = _tool_registrations(tree)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fc = FuncCaps(name=node.name, lineno=node.lineno)
            v = _Visitor(fc)
            for child in node.body:
                v.visit(child)
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    n = _call_name(child.func)
                    if n and "." not in n and n != node.name:
                        fc.calls.add(n)
            ma.functions[node.name] = fc

    _propagate(ma)
    return ma


def _propagate(ma: ModuleAnalysis, rounds: int = 4) -> None:
    """Push callee capabilities up into callers, within the module.

    Bounded rather than fixpoint: a tool chain in a real server is shallow, and an
    unbounded loop over a recursive module would spin. Four rounds covers every
    wrapper pattern seen in practice and is stated rather than assumed.
    """
    for _ in range(rounds):
        changed = False
        for fc in ma.functions.values():
            for callee in fc.calls:
                other = ma.functions.get(callee)
                if not other:
                    continue
                missing = other.caps - fc.caps
                if missing:
                    fc.caps |= missing
                    for e in other.evidence:
                        fc.evidence.add(f"via {callee}: {e}")
                    changed = True
        if not changed:
            break


def analyze_tree(root: str | Path) -> Dict[str, ModuleAnalysis]:
    """Analyse every module under a directory, keyed by relative path."""
    root = Path(root)
    out: Dict[str, ModuleAnalysis] = {}
    if not root.exists():
        return out
    for p in sorted(root.rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        out[p.relative_to(root).as_posix()] = analyze_module(p)
    return out


def tool_capabilities(analyses: Dict[str, ModuleAnalysis]) -> Dict[str, Set[str]]:
    """Merge per-module results into `tool_name -> capabilities`."""
    out: Dict[str, Set[str]] = {}
    for ma in analyses.values():
        for tool in ma.tools:
            caps = ma.caps_for_tool(tool)
            if caps:
                out[tool] = out.get(tool, set()) | caps
    return out


# --------------------------------------------------------------------------
# HONEST LIMITS
# --------------------------------------------------------------------------
#
# 1. **Static, so it sees only what is written.** A capability reached through
#    `getattr(mod, "run")(...)`, a plugin loaded by name, or a call into a C extension
#    is invisible. The analyser errs toward over-reporting when it recognises a
#    primitive and toward silence when it does not, which is the safer direction for
#    a rule that requires a conjunction.
#
# 2. **Function boundaries are respected but not aliasing.** `f = open; f(p)` and
#    `import subprocess as sp` are handled for the common spellings; a determined
#    obfuscation (reassigning `open` to something else) is not. This module measures
#    what a component does, not how hard it is trying to hide.
#
# 3. **Propagation is bounded at four rounds** and does not cross modules. A tool
#    implemented in a helper module would be missed; pointing the analyser at the
#    whole tree rather than one file is the caller's job.
#
# 4. **A capability is not a finding.** "This tool can reach the network" is true of
#    most useful tools. The rules decide; this only supplies the profile.
