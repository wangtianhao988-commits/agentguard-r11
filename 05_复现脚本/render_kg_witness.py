"""Render actual ablation graph witnesses without a server or graph dependency."""
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'07_修复验证/R7_kg_ablation'
summary = json.loads((OUT/'summary.json').read_text(encoding='utf-8'))
examples = []
for result in summary['results']:
    for item in result['examples']:
        examples.append({'label':f"{result['split']} / {result['mode']} / {item['case']}", **item})
data = json.dumps(examples, ensure_ascii=False).replace('<', '\\u003c')
html = '''<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<title>R7 安全图推理见证</title><style>
body{font:16px/1.6 system-ui,sans-serif;max-width:1150px;margin:40px auto;padding:0 20px;color:#192b3a;background:#f5f8fb}
select{width:100%;padding:12px;font:inherit}#path{display:flex;align-items:center;gap:10px;overflow:auto;margin:25px 0;padding:15px 0}
.node{min-width:145px;background:white;border:1px solid #b9c9d4;border-top:4px solid #186ca0;border-radius:5px;padding:12px;white-space:pre-wrap;font-size:14px}
.edge{min-width:120px;font-size:12px;text-align:center;color:#176497}table{border-collapse:collapse;width:100%;background:white}td,th{padding:10px;border:1px solid #ccd6df;text-align:left}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:white;padding:18px;font-size:13px}
</style><h1>R7 安全知识图谱：实际决策见证</h1>
<p>以下来自固定种子合成机制实验的实际输出，不能代替独立真实攻击验证。箭头表示算法查询返回的证据路径；指纹匹配和观察先后关系不构成模型因果证明。</p>
<select id="choose" aria-label="选择实验见证"></select><h2 id="title"></h2><div id="path"></div>
<h2>图节点与事实</h2><table><thead><tr><th>节点</th><th>类型</th><th>观测事实</th></tr></thead><tbody id="facts"></tbody></table>
<details><summary>完整 JSON 见证</summary><pre id="raw"></pre></details>
<script>const examples=DATA;
const choose=document.getElementById('choose');
examples.forEach((e,i)=>{let option=document.createElement('option');option.value=i;option.textContent=e.label;choose.append(option)});
function show(){const e=examples[Number(choose.value)];const w=e.witness;document.getElementById('title').textContent=w.rule_id+' — '+w.summary;
const path=document.getElementById('path');path.replaceChildren();const nodes=new Map(w.graph.nodes.map(n=>[n.id,n]));
const trail=w.path||[];if(trail.length){let ids=[trail[0].src,...trail.map(edge=>edge.dst)];ids.forEach((id,i)=>{let n=nodes.get(id);let box=document.createElement('div');box.className='node';box.textContent=id+'\\n'+n.kind;path.append(box);if(i<trail.length){let edge=document.createElement('div');edge.className='edge';edge.textContent=trail[i].relation+' →';path.append(edge)}})}else{path.textContent='授权路径不存在；参见 missing_relation。'}
const facts=document.getElementById('facts');facts.replaceChildren();w.graph.nodes.forEach(n=>{let row=document.createElement('tr');const {id,kind,...rest}=n;[id,kind,JSON.stringify(rest)].forEach(text=>{let cell=document.createElement('td');cell.textContent=text;row.append(cell)});facts.append(row)});document.getElementById('raw').textContent=JSON.stringify(w,null,2);}
choose.addEventListener('change',show);if(examples.length)show();</script></html>'''.replace('DATA',data)
(OUT/'graph_witness.html').write_text(html,encoding='utf-8')
print('Rendered actual graph witnesses:',len(examples))
