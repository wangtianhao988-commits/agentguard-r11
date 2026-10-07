"""Read public official resources only; no account cookies or login automation."""
import json
from pathlib import Path
import re
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'07_修复验证'
URL = 'https://www.chaspark.com/'
result = {'checked_on': '2026-10-04', 'original_task_attachment_checked_on': '2026-10-03', 'public_only': True, 'chaspark_url':
          URL+'#/races/competitions/1260023099017760768',
          'official_attachment': 'https://cpipc.acge.org.cn/sysFile/downFile.do?fileId=6b3ec28bade34a85985de511ec1b149c',
          'attachment_model_name_or_endpoint': False,
          'attachment_note': 'The official task describes a provided range but supplies no model name, model download, API endpoint or range download link.',
          'model_availability': 'unconfirmed; public absence does not exclude registered-team resources'}
provenance = OUT/'R4_official_provenance.json'
if provenance.exists():
    result['official_range_received'] = True
    result['official_range_model'] = 'deterministic llm-stub; README states no model API is required'
    result['model_availability'] = 'Official replay is available locally; real autonomous models are optional extra validation'
try:
    request = urllib.request.Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(request, timeout=20) as response:
        html = response.read().decode('utf-8')
        result['public_page_status'] = response.status
    (OUT/'R4_chaspark_public.html').write_text(html, encoding='utf-8')
    result['scripts'] = re.findall(r'<script[^>]+src=["\x27]([^"\x27]+)', html)
except Exception as error:
    result['public_page_error'] = type(error).__name__ + ': ' + str(error)
(OUT/'R4_official_resources.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps(result, ensure_ascii=False))
