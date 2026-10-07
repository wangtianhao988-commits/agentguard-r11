"""Verify actual container source against the preserved official archive."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MCP = ['customer-db', 'shell-runner', 'notes-sync', 'threat-intel',
       'gitlab', 'monitoring', 'knowledge', 'sandbox-exec']

def attest():
    provenance = json.loads((ROOT/'07_修复验证/R4_official_provenance.json').read_text(encoding='utf-8'))
    app, mcp = {}, {}
    for item in provenance['official_files']:
        name, digest = item['path'], item['sha256']
        if name.startswith('opspilot-app/') and name.endswith('.py') and not name.endswith('conftest.py'):
            app['/app/'+name.removeprefix('opspilot-app/')] = digest
        if name.startswith('skills/'):
            app['/app/'+name] = digest
        if name.startswith('mcp/_base/mcp_base/'):
            mcp['/app/mcp_base/'+name.removeprefix('mcp/_base/mcp_base/')] = digest
        elif name.startswith('mcp/'):
            mcp['/app/mcp_pkgs/'+name.removeprefix('mcp/')] = digest
    result = {}
    code = 'import pathlib,hashlib,json,sys; print(json.dumps({p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in json.loads(sys.argv[1])}))'
    for container, expected in [('agentrange-opspilot-app-1', app)] + [
            ('agentrange-mcp-'+name+'-1', mcp) for name in MCP]:
        response = subprocess.run(['docker', 'exec', container, 'python', '-c', code,
            json.dumps(list(expected))], capture_output=True, check=True, text=True)
        actual = json.loads(response.stdout)
        if actual != expected:
            raise RuntimeError('Container official source differs: '+container)
        image = subprocess.run(['docker', 'inspect', '--format', '{{.Image}}', container],
            capture_output=True, check=True, text=True).stdout.strip()
        result[container] = {'files_matched': len(expected), 'image': image,
            'aggregate_sha256': hashlib.sha256(json.dumps(actual, sort_keys=True).encode()).hexdigest()}
    return result

if __name__ == '__main__':
    result = attest()
    (ROOT/'07_修复验证/R4_official_runtime_attestation.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result))
