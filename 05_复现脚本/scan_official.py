"""Scan only the local agentrange project and preserved official supply chain."""
from pathlib import Path
import subprocess
import argparse

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--evidence-dir', type=Path)
parser.add_argument('--output-name', default='R6_inventory.json')
args = parser.parse_args()
if Path(args.output_name).name != args.output_name:
    raise ValueError('output-name must be a filename')
evidence_args = []
if args.evidence_dir:
    observations = args.evidence_dir.resolve(strict=True)
    relative = observations.relative_to(ROOT/'07_修复验证')
    evidence_args = ['--evidence-dir', '/evidence/'+relative.as_posix()]
official = ROOT/'06_赛题与第三方/官方靶场原包/agentrange'
if not (official/'docs/README.md').exists():
    raise RuntimeError('Preserved official range is missing')
subprocess.run(['docker', 'build', '-t', 'agentrange-guard-inventory-r6', '-f',
    str(ROOT/'track2/inventory/Dockerfile'), str(ROOT/'track2')], check=True)
subprocess.run(['docker', 'run', '--rm', '--name', 'guard-r6-scan',
    '--network', 'agentrange_opspilot-net',
    '--mount', 'type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock,readonly',
    '--mount', 'type=bind,source='+str(official)+',target=/range,readonly',
    '--mount', 'type=bind,source='+str(ROOT/'07_修复验证')+',target=/evidence',
    'agentrange-guard-inventory-r6', 'python', 'run_scan.py',
    '--out', '/evidence/'+args.output_name, '--docker-filter', 'agentrange',
    '--range-root', '/range', '--skills-root', '/range/skills', *evidence_args], check=True)
