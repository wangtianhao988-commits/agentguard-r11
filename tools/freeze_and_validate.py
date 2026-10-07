"""One formal run, gated on original service health and immutable source hashes."""
import hashlib
import json
import os
import platform
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT/'07_修复验证/external_r11_gemini'
REPORTS = ROOT/'reports'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    protocol = json.loads((DATA/'protocol.json').read_text(encoding='utf-8'))
    config = protocol['runtime_configuration']
    # No full run may begin with an offline verifier; no archived verdict reuse.
    with urllib.request.urlopen(config['GUARD_R11_INTENT_URL']+'/health', timeout=3) as response:
        assert response.status == 200
    assert not (DATA/'results/R12D_frozen').exists(), 'Formal run already started'
    preservation = json.loads((REPORTS/'r12d_original_preservation.json').read_text(encoding='utf-8'))
    for name, expected in preservation['original_python_sha256'].items():
        assert digest(Path(name)) == expected, name
    assert digest(ROOT/'05_复现脚本/evaluate_external_r10.py') == preservation['evaluator_unmodified_sha256']
    protocol['candidate'] = 'R12-D minimal boundary; original R11 semantic verifier reused'
    for name in ('track2/collector/inline_guard.py', 'track2/detector/external_boundary.py'):
        protocol['sources']['R10'][name] = digest(ROOT/name)
    (DATA/'protocol.json').write_text(json.dumps(protocol, ensure_ascii=False, indent=2), encoding='utf-8')
    (DATA/'protocol.sha256').write_text(digest(DATA/'protocol.json')+'\n', encoding='utf-8')
    subprocess.run(['git', 'config', 'core.autocrlf', 'false'], cwd=ROOT, check=True)
    subprocess.run(['git', 'add', 'track2', 'tools', 'reports'], cwd=ROOT, check=True)
    subprocess.run(['git', 'commit', '-m', 'Freeze minimal external boundary before full validation'], cwd=ROOT, check=True)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    environment = {**os.environ, **config, 'PYTHONUTF8': '1', 'GUARD_R12_BOUNDARY': '1',
                   'GUARD_R12_AUDIT_PATH': str(REPORTS/'r12d_runtime_events.jsonl')}
    command = [sys.executable, str(ROOT/'05_复现脚本/evaluate_external_r10.py'), '--version', 'R10',
               '--dataset-name', 'external_r11_gemini', '--output-name', 'R12D_frozen']
    manifest = {'started_utc': datetime.now(timezone.utc).isoformat(), 'freeze_commit': commit,
                'seed': 42, 'python': sys.version, 'platform': platform.platform(), 'command': command,
                'runtime_configuration': {**config, 'GUARD_R12_BOUNDARY': '1',
                                          'GUARD_R12_AUDIT_PATH': environment['GUARD_R12_AUDIT_PATH']},
                'protocol_sha256': digest(DATA/'protocol.json'),
                'selection_sha256': digest(DATA/'selection.json'),
                'benchmark_manifest_sha256': digest(DATA/'download_manifest.json'),
                'source_sha256': protocol['sources']['R10'], 'original_preservation_verified': True}
    (REPORTS/'r12d_run_manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    with (REPORTS/'r12d_full_run.log').open('w', encoding='utf-8') as log:
        result = subprocess.run(command, cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT)
    manifest['returncode'] = result.returncode
    manifest['completed_utc'] = datetime.now(timezone.utc).isoformat()
    (REPORTS/'r12d_run_manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    for name, expected in manifest['source_sha256'].items():
        assert digest(ROOT/name) == expected, 'Source changed during formal run: '+name
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
