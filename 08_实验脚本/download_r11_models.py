"""Download only pinned public model data; never import remote model code."""
import concurrent.futures, hashlib, json
from pathlib import Path
import requests

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = ROOT / '07_修复验证/model_candidates'

def download(repo, revision, files, directory):
    directory.mkdir(parents=True, exist_ok=True)
    metadata = requests.get(f'https://huggingface.co/api/models/{repo}/revision/{revision}?blobs=true', timeout=60)
    metadata.raise_for_status()
    metadata = metadata.json()
    assert metadata['sha'] == revision
    siblings = {v['rfilename']: v for v in metadata['siblings']}
    manifest = {'repository': repo, 'revision': revision, 'files': []}
    for name in files:
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        expected = siblings[name]
        expected_sha = expected.get('lfs', {}).get('sha256')
        if not target.exists():
            partial = target.with_suffix(target.suffix + '.partial')
            with requests.get(f'https://huggingface.co/{repo}/resolve/{revision}/{name}', stream=True, timeout=(30, 120)) as response:
                response.raise_for_status()
                with partial.open('wb') as stream:
                    for chunk in response.iter_content(1024 * 1024):
                        stream.write(chunk)
            partial.replace(target)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        assert target.stat().st_size == expected['size'], name
        if expected_sha:
            assert digest == expected_sha, name
        manifest['files'].append({'path': name, 'bytes': target.stat().st_size, 'sha256': digest})
        print(json.dumps({'downloaded': name, 'bytes': target.stat().st_size}, ensure_ascii=False), flush=True)
    (directory / 'provenance.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    return manifest

if __name__ == '__main__':
    jobs = [
        ('marklkelly/bert-tiny-injection-detector', 'a599dc7ab2552bca0d097e2b4afa7cb584638da4',
         ['onnx/opset11/model.int8.onnx', 'tokenizer.json', 'config.json', 'deployment/fastly/calibrated_thresholds.json', 'LICENSE', 'NOTICE', 'README.md'], ROOT / 'track2/models/r11_tiny'),
        ('Qwen/Qwen3-0.6B-GGUF', '23749fefcc72300e3a2ad315e1317431b06b590a',
         ['Qwen3-0.6B-Q8_0.gguf', 'LICENSE', 'README.md'], CANDIDATES / 'qwen3_06b'),
        ('patronus-studio/wolf-defender-prompt-injection-small', 'bcab2eff97bcabd7227849639e2d0d7a61b46c92',
         ['onnx/int8_int4_embeddings/model.onnx', 'tokenizer.json', 'tokenizer_config.json', 'config.json', 'LICENSE', 'README.md'], ROOT / 'track2/models/r11_wolf'),
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        for result in pool.map(lambda job: download(*job), jobs):
            print(json.dumps({'completed': result['repository']}), flush=True)
