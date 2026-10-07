"""Preserve and verify the user-supplied official archive without executing it."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT/'06_赛题与第三方/官方靶场原包'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('archive', type=Path)
    parser.add_argument('--verify-url', action='store_true')
    args = parser.parse_args()
    source = args.archive.resolve(strict=True)
    DEST.mkdir(parents=True, exist_ok=True)
    kept = DEST/'AgentRange-player.zip'
    if kept.exists() and kept.read_bytes() != source.read_bytes():
        raise RuntimeError('Existing preserved archive differs; refusing overwrite')
    if not kept.exists():
        shutil.copy2(source, kept)
    official = DEST/'agentrange'
    manifest, changes, diffs = [], [], []
    current = ROOT/'_scratch/competition/agentrange'
    with zipfile.ZipFile(kept) as archive:
        if archive.testzip() is not None:
            raise RuntimeError('Corrupt official archive')
        for item in archive.infolist():
            rel = PurePosixPath(item.filename.replace('\\', '/'))
            if rel.is_absolute() or '..' in rel.parts or any(':' in p for p in rel.parts):
                raise ValueError('Unsafe archive path')
            if stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError('Archive symlinks are not accepted')
            path = official.joinpath(*rel.parts)
            if item.is_dir():
                path.mkdir(parents=True, exist_ok=True)
                continue
            data = archive.read(item)
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() and path.read_bytes() != data:
                raise RuntimeError('Preserved source changed: '+str(rel))
            if not path.exists():
                path.write_bytes(data)
            manifest.append({'path': rel.as_posix(), 'sha256': hashlib.sha256(data).hexdigest()})
            active = current.joinpath(*rel.parts)
            if not active.exists() or active.read_bytes() != data:
                changes.append(rel.as_posix())
                if active.exists():
                    diffs.extend(difflib.unified_diff(data.decode().splitlines(True),
                        active.read_text(encoding='utf-8').splitlines(True),
                        fromfile='official/'+str(rel), tofile='working/'+str(rel)))
    result = {'archive_sha256': hashlib.sha256(kept.read_bytes()).hexdigest(),
        'archive_bytes': kept.stat().st_size, 'official_files': manifest,
        'changed_existing_files': changes,
        'scope': 'Original file comparisons; additional defense files are not official assets',
        'model': 'Official README explicitly uses deterministic llm-stub and does not require a model API'}
    if args.verify_url:
        url = 'https://cpipc.acge.org.cn/sysFile/downFile.do?fileId=5fa4f046036f426f905c8fb6e575339e'
        with urllib.request.urlopen(url, timeout=20) as response:
            website_archive = response.read(1048577)
        if len(website_archive) > 1048576:
            raise RuntimeError('Unexpectedly large official download; review before continuing')
        result['download_url'] = url
        result['website_archive_sha256'] = hashlib.sha256(website_archive).hexdigest()
        result['website_archive_matches_supplied'] = website_archive == kept.read_bytes()
    out = ROOT/'07_修复验证'
    (out/'R4_official_provenance.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    (out/'R4_official_source_diff.patch').write_text(''.join(diffs), encoding='utf-8')
    print(json.dumps({'files': len(manifest), 'differences': changes, 'sha256': result['archive_sha256']}))

if __name__ == '__main__':
    main()
