"""Asset discovery by probing -- the M1/M2 half of the brief.

Design rule
-----------
Everything here is discovered from the **deployed system**: the container runtime,
the network, the MCP protocol and the filesystem. Nothing reads a manifest of the
answer. That is not a stylistic preference -- the brief requires a general algorithm
and says the range is only for validation, so a scanner that parses
`docker-compose.yml` would score 99% here and 0% on the next agent.

Four discovery sources, in increasing order of what they reveal:

  1. **Container runtime** (Docker API): services, images, ports, networks, env.
     Gives the coarse inventory and, critically, the *network topology* -- which is
     how "this service can reach the internet while its peers cannot" becomes a
     finding rather than an assumption.
  2. **HTTP surface probing**: which services actually answer, and what they say.
  3. **MCP protocol**: `initialize` then `tools/list` on every endpoint that speaks
     JSON-RPC. This is the only way to learn a tool's *declared* surface, and the
     comparison against its *actual* surface is where the backdoor shows up.
  4. **Filesystem**: skill directories, their manifests, and -- the part manifests
     never mention -- whether a `scripts/` directory exists and what it contains.

Honest limits are at the bottom of this file.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import httpx

# --------------------------------------------------------------------------
# asset model
# --------------------------------------------------------------------------

AGENT = "agent"
FRAMEWORK = "framework"
MODEL = "model"
MCP_SERVER = "mcp_server"
TOOL = "tool"
SKILL = "skill"
DATASTORE = "datastore"
SERVICE = "service"
NETWORK = "network"


@dataclass
class Asset:
    asset_id: str
    kind: str
    name: str
    discovered_by: str
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> Dict[str, Any]:
        return {"asset_id": self.asset_id, "kind": self.kind, "name": self.name,
                "discovered_by": self.discovered_by, "attributes": self.attributes}


@dataclass
class Edge:
    src: str
    dst: str
    relation: str

    def to_json(self) -> Dict[str, Any]:
        return {"src": self.src, "dst": self.dst, "relation": self.relation}


class AssetGraph:
    def __init__(self) -> None:
        self.assets: Dict[str, Asset] = {}
        self.edges: List[Edge] = []
        # Raw skill records with their bodies. Kept beside the graph rather than
        # inside `Asset.attributes` because the body is prose, not a graph property,
        # and `risks.py` needs it verbatim.
        self.raw_skills: List[Dict[str, Any]] = []

    def add(self, a: Asset) -> Asset:
        self.assets[a.asset_id] = a
        return a

    def link(self, src: str, dst: str, relation: str) -> None:
        if src in self.assets and dst in self.assets:
            self.edges.append(Edge(src, dst, relation))

    def by_kind(self, kind: str) -> List[Asset]:
        return [a for a in self.assets.values() if a.kind == kind]

    def summary(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for a in self.assets.values():
            out[a.kind] = out.get(a.kind, 0) + 1
        return out

    def to_json(self) -> Dict[str, Any]:
        return {"assets": [a.to_json() for a in self.assets.values()],
                "edges": [e.to_json() for e in self.edges],
                "summary": self.summary()}


# --------------------------------------------------------------------------
# 1. container runtime
# --------------------------------------------------------------------------


def _docker(args: List[str], timeout: int = 30) -> Any:
    """Deprecated shell-out kept only as a fallback for host-side runs.

    The container build installed `docker.io` from Debian and the CLI was still not
    on PATH, which silently emptied the entire service inventory -- and with it every
    configuration finding, since they all read env vars off services. Shelling out to
    a binary that may or may not exist is the wrong dependency for a scanner; the
    socket API below has none.
    """
    try:
        p = subprocess.run(["docker"] + args, capture_output=True, text=True, timeout=timeout)
        if p.returncode != 0:
            return None
        return p.stdout
    except Exception:  # noqa: BLE001
        return None


DOCKER_SOCK = os.getenv("DOCKER_SOCK", "/var/run/docker.sock")
_DOCKER_API_VERSION = "v1.44"


def docker_api(path: str, timeout: float = 10.0) -> Any:
    """Call the Docker Engine API over the unix socket. No CLI, no SDK dependency."""
    try:
        transport = httpx.HTTPTransport(uds=DOCKER_SOCK)
        with httpx.Client(transport=transport, base_url="http://docker",
                          timeout=timeout) as c:
            r = c.get(f"/{_DOCKER_API_VERSION}{path}")
            if r.status_code >= 400:
                return None
            return r.json()
    except Exception:  # noqa: BLE001
        return None


def discover_containers(g: AssetGraph, name_filter: str = "") -> List[Dict[str, Any]]:
    """Enumerate running containers and everything the runtime knows about them.

    `name_filter` scopes the scan to one deployment; a real product would take a
    namespace, a k8s label selector or a host list. It is a *scope*, not an answer
    key -- the scanner still has to find what is inside the scope.
    """
    listing = docker_api("/containers/json")
    if listing is None:
        # Fall back to the CLI for host-side runs where the socket is not mounted.
        raw = _docker(["ps", "--format", "{{.Names}}"])
        if not raw:
            raise RuntimeError(
                "cannot reach the container runtime: neither the Docker socket at "
                f"{DOCKER_SOCK} nor the docker CLI is available. An inventory scan "
                "that silently returns zero services would still report 'no risk "
                "found', which is the worst possible failure mode.")
        names = [n.strip() for n in raw.splitlines() if n.strip()]
        infos = []
        for name in names:
            txt = _docker(["inspect", name])
            if txt:
                try:
                    infos.append(json.loads(txt)[0])
                except Exception:  # noqa: BLE001
                    continue
    else:
        infos = []
        for item in listing:
            iid = item.get("Id")
            if not iid:
                continue
            info = docker_api(f"/containers/{iid}/json")
            if info:
                infos.append(info)

    if name_filter:
        infos = [i for i in infos if name_filter in (i.get("Name") or "")]

    out = []
    for info in infos:
        name = (info.get("Name") or "").lstrip("/")
        out.append(info)
        cfg = info.get("Config") or {}
        env = {}
        for kv in cfg.get("Env") or []:
            if "=" in kv:
                k, v = kv.split("=", 1)
                env[k] = v
        nets = list(((info.get("NetworkSettings") or {}).get("Networks") or {}).keys())
        ports = []
        for cp, binds in ((info.get("NetworkSettings") or {}).get("Ports") or {}).items():
            if binds:
                ports.append({"container": cp, "host": [b.get("HostPort") for b in binds]})
        aid = f"service:{name}"
        g.add(Asset(aid, SERVICE, name, "docker.api",
                    {"image": cfg.get("Image", ""),
                     "networks": nets,
                     "published_ports": ports,
                     "env": env,
                     "entrypoint": (cfg.get("Entrypoint") or []) + (cfg.get("Cmd") or [])}))
        for net in nets:
            nid = f"network:{net}"
            g.add(Asset(nid, NETWORK, net, "docker.api"))
            g.link(aid, nid, "attached_to")
        for dep in _infer_dependencies(env, nets):
            g.link(aid, dep, "depends_on")
    return out


def _infer_dependencies(env: Dict[str, str], nets: List[str]) -> List[str]:
    """Edges from service-URL-shaped env values.

    Looks for values that are URLs and keeps the host part. That is how
    `LLM_BASE=http://llm-stub:8000/v1` becomes an edge to the `llm-stub` service
    without anyone writing down that the agent calls an LLM.
    """
    out: Set[str] = set()
    for v in env.values():
        for m in re.finditer(r"https?://([A-Za-z0-9_.-]+)(?::\d+)?", v or ""):
            out.add(f"service:{m.group(1)}")
    return sorted(out)


# --------------------------------------------------------------------------
# 2/3. protocol probing
# --------------------------------------------------------------------------


def probe_http(url: str, timeout: float = 4.0) -> Dict[str, Any]:
    try:
        r = httpx.get(url, timeout=timeout)
        body: Any
        try:
            body = r.json()
        except Exception:  # noqa: BLE001
            body = r.text[:300]
        return {"ok": r.status_code < 500, "status": r.status_code, "body": body}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": type(e).__name__}


def probe_mcp(base_url: str, server_name: str, g: AssetGraph, timeout: float = 6.0) -> Dict[str, Any]:
    """`initialize` + `tools/list`. Returns what the server DECLARES.

    The declared list is compared later against what the process can actually be
    asked to do (see `risks.py`); the gap between the two is the whole point.
    """
    ep = base_url.rstrip("/")
    info: Dict[str, Any] = {"endpoint": ep, "name": server_name}
    try:
        c = httpx.Client(timeout=timeout)
        r = c.post(ep, json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                             "params": {"protocolVersion": "2025-06-18",
                                        "capabilities": {}, "clientInfo": {"name": "scanner"}}})
        info["initialize"] = r.json().get("result") if r.status_code < 500 else None
        r = c.post(ep, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        if r.status_code >= 500:
            info["tools"] = []
            return info
        payload = r.json()
        tools = ((payload.get("result") or {}).get("tools")) or []
        info["tools"] = tools
        info["n_tools"] = len(tools)
    except Exception as e:  # noqa: BLE001
        info["error"] = f"{type(e).__name__}: {e}"
        info["tools"] = []
    return info


def register_mcp_assets(g: AssetGraph, probes: List[Dict[str, Any]],
                        code_caps: Optional[Dict[str, Any]] = None) -> None:
    """Record each probed server and its declared tools.

    `code_caps` (tool name -> capability set, from `codecap`) is attached to the tool
    asset so the detector can combine what the declaration says with what the code
    does. Without it a backdoor whose description is innocuous is invisible: the
    declaration is the attacker's own words.
    """
    code_caps = code_caps or {}
    for p in probes:
        sid = f"mcp:{p['name']}"
        g.add(Asset(sid, MCP_SERVER, p["name"], "mcp.initialize",
                    {"endpoint": p["endpoint"],
                     "server_info": (p.get("initialize") or {}).get("serverInfo"),
                     "protocol_version": (p.get("initialize") or {}).get("protocolVersion"),
                     "n_tools_declared": len(p.get("tools") or [])}))
        for t in p.get("tools") or []:
            tname = t.get("name")
            tid = f"tool:{p['name']}.{tname}"
            g.add(Asset(tid, TOOL, f"{p['name']}.{tname}", "mcp.tools/list",
                        {"description": t.get("description", ""),
                         "input_schema": t.get("inputSchema"),
                         "server": p["name"],
                         "declared_in_tools_list": True,
                         "code_caps": sorted(code_caps.get(f"{p['name']}.{tname}",
                             code_caps.get(tname, set())))}))
            g.link(sid, tid, "exposes")


# --------------------------------------------------------------------------
# 4. filesystem
# --------------------------------------------------------------------------


FRONTMATTER = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)$", re.S)


def parse_skill(path: Path) -> Optional[Dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:  # noqa: BLE001
        return None
    m = FRONTMATTER.match(text)
    if not m:
        return None
    fm_raw, body = m.group(1), m.group(2)
    meta: Dict[str, Any] = {}
    for line in fm_raw.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
    # Handles both `allowed-tools: [a, b]` and a bare `a, b`; no YAML dependency so
    # the scanner stays runnable in a minimal container.
    allowed = meta.get("allowed-tools", "")
    allowed = allowed.strip().strip("[]")
    tools = [t.strip().strip("'\"") for t in allowed.split(",") if t.strip()]
    return {"name": meta.get("name", path.parent.name),
            "description": meta.get("description", ""),
            "allowed_tools": tools, "body": body, "path": str(path)}


def discover_skills(g: AssetGraph, root: str | Path) -> List[Dict[str, Any]]:
    root = Path(root)
    out: List[Dict[str, Any]] = []
    if not root.exists():
        return out
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        md = d / "SKILL.md"
        if not md.exists():
            continue
        sk = parse_skill(md)
        if not sk:
            continue
        # The manifest describes intent; the directory describes fact. Record both.
        scripts = sorted(str(p.relative_to(d).as_posix())
                         for p in d.rglob("*") if p.is_file() and p.name != "SKILL.md")
        sk["scripts"] = scripts
        sk["has_scripts_dir"] = (d / "scripts").is_dir()
        out.append(sk)
        aid = f"skill:{sk['name']}"
        g.add(Asset(aid, SKILL, sk["name"], "filesystem.SKILL.md",
                    {"description": sk["description"], "allowed_tools": sk["allowed_tools"],
                     "path": str(md), "scripts": scripts,
                     "has_scripts_dir": sk["has_scripts_dir"],
                     "body_chars": len(sk["body"])}))
        for s in scripts:
            sid = f"skill_script:{sk['name']}/{s}"
            g.add(Asset(sid, "skill_script", f"{sk['name']}/{s}", "filesystem.walk",
                        {"path": str(d / s)}))
            g.link(aid, sid, "contains")
    return out


# --------------------------------------------------------------------------
# top level
# --------------------------------------------------------------------------


def scan(docker_name_filter: str = "agentrange",
         skills_root: Optional[str] = None,
         mcp_targets: Optional[Dict[str, str]] = None,
         http_targets: Optional[Dict[str, str]] = None,
         code_caps: Optional[Dict[str, Any]] = None) -> Tuple[AssetGraph, Dict[str, Any]]:
    g = AssetGraph()
    raw: Dict[str, Any] = {"started": time.time()}

    containers = discover_containers(g, docker_name_filter)
    raw["n_containers"] = len(containers)
    raw["containers"] = [{"name": (c.get("Name") or "").lstrip("/"),
                          "image": (c.get("Config") or {}).get("Image"),
                          "networks": list(((c.get("NetworkSettings") or {}).get("Networks") or {}).keys())}
                         for c in containers]

    # Classify roles from observable evidence, not from a name list. The signals are
    # structural: does it listen, does it hold a datastore, does it speak JSON-RPC.
    for c in containers:
        name = (c.get("Name") or "").lstrip("/")
        cfg = c.get("Config") or {}
        env = {}
        for kv in cfg.get("Env") or []:
            if "=" in kv:
                k, v = kv.split("=", 1)
                env[k] = v
        image = (cfg.get("Image") or "").lower()
        cmd = " ".join((cfg.get("Entrypoint") or []) + (cfg.get("Cmd") or [])).lower()
        aid = f"service:{name}"

        if "postgres" in image or "postgres" in cmd:
            g.add(Asset(f"datastore:{name}", DATASTORE, name, "docker.inspect.image",
                        {"engine": "postgres", "env_keys": sorted(env)}))
            g.link(aid, f"datastore:{name}", "hosts")
        if "llm" in name or "llm" in cmd or "model" in cmd:
            g.add(Asset(f"model-endpoint:{name}", MODEL, name, "docker.inspect.cmd",
                        {"env_keys": sorted(env)}))
        if "langflow" in image or "langflow" in name:
            g.add(Asset(f"framework:{name}", FRAMEWORK, name, "docker.inspect.image",
                        {"image": cfg.get("Image"), "env_keys": sorted(env)}))
        # An agent is a service that both serves HTTP and holds credentials to call
        # other components. Both facts are needed; either alone matches too much.
        outbound = _infer_dependencies(env, [])
        has_model_endpoint = any("llm" in k.lower() or "openai" in k.lower()
                                 for k, v in env.items() if str(v).startswith("http"))
        if has_model_endpoint and outbound and any(k in env for k in ("JWT_SECRET", "SECRET_KEY", "TOKEN", "api_key")):
            g.add(Asset(f"agent:{name}", AGENT, name, "docker.inspect.heuristic",
                        {"outbound_edges": outbound, "env_keys": sorted(env)}))
        for dep in outbound:
            g.link(aid, dep, "calls")

    # Resolve logical Compose names and network aliases to discovered service IDs.
    # URL hosts such as llm-stub are not the container name agentrange-llm-stub-1.
    aliases = {}
    for c in containers:
        name = (c.get("Name") or "").lstrip("/")
        aid = f"service:{name}"
        aliases[name] = aid
        labels = (c.get("Config") or {}).get("Labels") or {}
        logical = labels.get("com.docker.compose.service")
        if logical:
            aliases[logical] = aid
        for net in ((c.get("NetworkSettings") or {}).get("Networks") or {}).values():
            for alias in net.get("Aliases") or []:
                aliases[alias] = aid
    for edge in g.edges:
        if edge.dst.startswith("service:"):
            edge.dst = aliases.get(edge.dst.split(":", 1)[1], edge.dst)
    # AssetGraph.link discards unresolved endpoints. Rebuild these links after
    # alias resolution; rewriting existing edges alone would leave zero links.
    for c in containers:
        name = (c.get("Name") or "").lstrip("/")
        env = dict(kv.split("=", 1) for kv in (c.get("Config") or {}).get("Env") or []
                   if "=" in kv)
        for dep in _infer_dependencies(env, []):
            target = aliases.get(dep.split(":", 1)[1])
            if target and not any(e.src == f"service:{name}" and e.dst == target
                                  and e.relation == "calls" for e in g.edges):
                g.link(f"service:{name}", target, "calls")

    probes = []
    known_services = {a.name: a.asset_id for a in g.by_kind(SERVICE)}
    container_scan_worked = bool(known_services)
    for server, url in (mcp_targets or {}).items():
        pr = probe_mcp(url, server, g)
        probes.append(pr)
        # Reconcile the probed endpoint with a service the runtime already reported,
        # rather than inventing a second node for the same thing. Docker names these
        # `agentrange-mcp-notes-sync-1` while the probe key is `notes-sync`, so an
        # exact-match test failed and the inventory double-counted all 8 servers.
        matched = None
        for name, aid in known_services.items():
            if server in name:
                matched = aid
                break
        if matched:
            g.link(f"mcp:{server}", matched, "runs_in")
            g.link(matched, f"mcp:{server}", "hosts")
        elif not container_scan_worked:
            # No runtime access at all: fall back to registering the endpoint so a
            # network-only scan still produces something. Only in this case, because
            # otherwise the service is already in the graph.
            g.add(Asset(f"service:{server}", SERVICE, server, "mcp.probe.reconstructed",
                        {"endpoint": url}))
    register_mcp_assets(g, probes, code_caps)
    raw["mcp_probes"] = probes

    skills = discover_skills(g, skills_root) if skills_root else []
    g.raw_skills = skills
    raw["skills"] = skills

    if http_targets:
        raw["http"] = {k: probe_http(v) for k, v in http_targets.items()}

    # Link the agent to the skills it can load: the skills root is mounted into it.
    agents = g.by_kind(AGENT)
    for a in agents:
        for s in skills:
            g.link(a.asset_id, f"skill:{s['name']}", "may_load")
        for p in probes:
            g.link(a.asset_id, f"mcp:{p['name']}", "may_call")

    raw["finished"] = time.time()
    raw["elapsed_s"] = round(raw["finished"] - raw["started"], 3)
    return g, raw


# --------------------------------------------------------------------------
# HONEST LIMITS
# --------------------------------------------------------------------------
#
# 1. **Scope comes from a filter, not from discovery.** `docker_name_filter` and the
#    MCP target list are inputs. A scanner that must find its own scope needs a
#    network sweep, which is a different (and noisier) problem.
#
# 2. **Classification uses heuristics on image names, commands and env keys.** An
#    agent deployed as a plain `python:3.12-slim` with no telltale env would be
#    missed by the "is it an agent" test. The test requires two independent facts
#    precisely to limit that, but it is still a heuristic and is labelled as one in
#    each asset's `discovered_by`.
#
# 3. **Dependency edges come from URL-shaped env values.** Dependencies wired at
#    runtime (service discovery, a config server) yield no edge.
#
# 4. **Only `tools/list` is probed on MCP.** `resources/*` and `prompts/*` are not
#    enumerated, so an injection surface reachable only through those is not
#    inventoried. This range does not implement them; a real one might.
#
# 5. **Nothing here verifies that a declared asset is healthy.** A registered but
#    dead server still appears in the graph with its declared tools.
