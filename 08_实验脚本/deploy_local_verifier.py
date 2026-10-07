"""Owned R11 local model only; pinned image and file, bounded CPU/RAM/KV cache."""
import hashlib,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
models=ROOT/'07_修复验证/model_candidates/qwen3_4b'
model=models/'Qwen3-4B-Q4_K_M.gguf'
expected='7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5'
digest=hashlib.file_digest(model.open('rb'),'sha256').hexdigest()
if digest!=expected:raise RuntimeError('Pinned model SHA mismatch')
config={'services':{'verifier':{
 'image':'ghcr.io/ggml-org/llama.cpp@sha256:ef08b5a98b1170f2b62177be0a4027c88a84043c55afbf190dd18b9e7cdcfebf',
 'container_name':'agentrange-r11-verifier','cpus':2,'mem_limit':'6g','memswap_limit':'6g',
 'read_only':True,'tmpfs':['/tmp:size=134217728'],
 'environment':{'GGML_CUDA_DISABLE_GRAPHS':'1'},
 'ports':['127.0.0.1:8116:8080'],'volumes':[{'type':'bind','source':str(models),'target':'/models','read_only':True}],
 'networks':['range'],'deploy':{'resources':{'reservations':{'devices':[{'driver':'nvidia','count':'all','capabilities':['gpu']}]}}},
 'command':['-m','/models/'+model.name,'--host','0.0.0.0','--port','8080','--ctx-size','8192','--threads','2','--threads-batch','2','--parallel','2','--jinja','--n-gpu-layers','99','--flash-attn','on','--cache-ram','128','--ctx-checkpoints','0']
 }},'networks':{'range':{'external':True,'name':'agentrange_opspilot-net'}}}
out=ROOT/'07_修复验证/local_verifier';out.mkdir(exist_ok=True)
(out/'compose.json').write_text(json.dumps(config,indent=2),encoding='utf8')
(out/'resource_policy.json').write_text(json.dumps({'model_sha256':expected,'memory_bytes':6*1024**3,'kv_ram_cache_mib':128,'context_checkpoints':0,'cuda_graphs':False,'note':'All model-service CPU must be included in qualification. GPU memory/usage reported separately; model approval never grants permission.'},indent=2))
# This name is an explicitly owned fixture, not any unrelated application.
inspect=subprocess.run(['docker','inspect','agentrange-r11-verifier'],capture_output=True,text=True)
if inspect.returncode==0:
 prior=json.loads(inspect.stdout)[0]
 if prior['Config']['Labels'].get('com.docker.compose.project')!='agentrange-r11-model':raise RuntimeError('Refuse non-owned container replacement')
 subprocess.run(['docker','rm','-f','agentrange-r11-verifier'],check=True)
subprocess.run(['docker','compose','-p','agentrange-r11-model','-f',str(out/'compose.json'),'up','-d','--no-build','verifier'],check=True)
