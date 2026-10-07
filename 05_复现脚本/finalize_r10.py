"""Create current reports from measured outcomes, including failed requirements."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'07_修复验证'
def read(name):return json.loads((OUT/name).read_text(encoding='utf-8'))
cpu=read('R10_cpu_optimized/measurement.json');initial=read('R10_cpu_pair/measurement.json')
assert cpu['status']=='completed' and initial['status']=='completed'
for rel,sha in cpu['source_sha256'].items():assert hashlib.sha256((ROOT/rel).read_bytes()).hexdigest()==sha
for rel,sha in cpu['driver_source_sha256'].items():
    path=ROOT/rel
    if hashlib.sha256(path.read_bytes()).hexdigest()!=sha:
        assert rel=='05_复现脚本/deploy_r3.py'
        assert hashlib.sha256((OUT/'R10_cpu_optimized/driver_snapshot/deploy_r3.py').read_bytes()).hexdigest()==sha
review=read('R10_review_dynamic/verification.json');assert review['tests']==126 and all(r['exit_code']==0 for r in review['checks'])
runtime=read('R10_review_dynamic/runtime.json');enforcement=read('R10_review_dynamic/enforcement.json')
external={v:read('external_r10/results/'+v+'/summary.json') for v in ['R9.1','R10_initial','R10']}
public=read('external_r10/public_test_summary.json');response=read('R10_client_response.json');static=read('R10_static_score.json')
summary={'version':'R10','regressions':126,'verification':review,'official_runtime':runtime,'official_enforcement':enforcement,
    'static':static,'external':external,'public_text_test':public,'paired':read('external_r10/paired_summary.json'),
    'cpu_initial_percent':initial['max'],'cpu_dynamic_percent':cpu['max'],'cpu_pair_count':len(cpu['pairs']),
    'cpu_scope':'single same-PID original full 5200-event pair, offered 40 events/s, single-core incremental cost; not whole-range absolute CPU or stable bound',
    'client_response':{k:v for k,v in response.items() if k!='requests'},'audit':read('R10_review_dynamic/audit.json'),
    'control_http':read('R10_control_http.json'),'business_benchmark':{k:v for k,v in read('R10_business_benchmark.json').items() if k!='cases'},
    'control_corpus':{k:v for k,v in read('R10_control_corpus.json').items() if k!='cases'},
    'restart':{k:v for k,v in read('R10_restart_check.json').items() if k!='health_after'},
    'external_95pct_achieved':False,'cpu_5pct_achieved':cpu['max']<5,'all_competition_requirements_achieved':False,
    'real_generative_model_closed_loop_completed':False,'official_stub_is_not_generative_model':True}
(OUT/'qualification_summary_r10.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
a=external['R9.1']['historically_successful'];b=external['R10']['historically_successful'];normal=external['R10']['benign']
report=f'''# AgentGuard R10 增强作品与检测报告

R10 已实现并验证固定计划权限绑定、控制与数据隔离、业务数据传播账本及学习型语义检测。**当前不能宣称全面达标：外部历史拦截机会为 {b['validated_interception']}/{b['n']}（{100*b['validated_interception']/b['n']:.2f}%），CPU 实测 {cpu['max']:.2f}% 均未达到目标。** 可交付源代码与复验证据，不能把本版本描述为通过所有比赛门槛的成品。

## 一、实测结果与指标边界

|项目|R10 结果|结论及范围|
|---|---|---|
|官方静态资产|42/42，精确率100%|固定官方真值通过；不代表所有外部 Skills/MCP|
|官方静态风险|13/13；19/19发现匹配|固定真值通过，两个诱饵未误报|
|官方攻击拒绝|56项Agent + 24项框架|全部拒绝；官方确定性 llm-stub|
|官方正常任务|5120次，误拒绝0、告警0|本轮负载通过；未证明未知业务零损失|
|Llama 历史成功攻击的可验证拦截机会|{a['validated_interception']}/{a['n']} → {b['validated_interception']}/{b['n']}|21.53% → 30.79%；未达95%，不是闭环ASR|
|Llama 正常任务误拒绝|{normal['refused']}/{normal['n']}（{100*normal['refused']/normal['n']:.2f}%）|低于5%，但未满足外部业务零误拦|
|公开文本语义检出|31/60（51.67%）|误报0/56；独立文本分类，不是Agent防御率|
|CPU 增量单核占用|{initial['max']:.2f}% → {cpu['max']:.2f}%|仍超过5%；两个不同冻结版本各一轮|
|客户端全请求耗时|攻击最大{response['attack']['max_ms']:.2f}ms，正常最大{response['benign']['max_ms']:.2f}ms|240次测试无HTTP错误，当前负载低于1秒|
|回归与复验|126项测试，{len(review['checks'])}组检查全部通过|正确性通过不等同于所有性能门槛通过|

全量外部评估含 2,847 条攻击轨迹、132 条正常轨迹，模型为 meta-llama/Llama-3.3-70B-Instruct，覆盖 direct、ignore_previous、important_instructions。R10 拒绝攻击轨迹515条，其中494条拒绝位置能够对齐到已观察注入之后；历史成功攻击367条中122条被拒绝，113条是严格可验证机会。另9条拒绝不能对齐注入之后，不能计作攻击链阻断。配对比较保留R9.1原有79条可验证机会，新增34条，尚有254条未拦截。

## 二、数据划分与失败记录

公开模型、训练数据、AgentDojo 源码与轨迹均固定提交并保存摘要。公开 deepset 训练数据和 R9.1 已使用的开发数据用于训练；按用户任务分组并排除跨组重复文本。新 Llama 轨迹在原始源代码与模型冻结后下载。因CPU失败，在未阅读测试内容时改为实际长度推理，并只用原开发数据重新校准。`protocol_initial.json`、当前 `protocol.json`、初版源代码与模型均保留。

原始填充版本在相同367条历史成功攻击上为110条可验证机会；最终版本113条。这两个版本均已冻结并分别回放。没有使用这些外部结果再次调整阈值。公开文本测试116条与训练/校准没有精确文本重叠。

首次 Llama 回放把文本块列表误当字符串，导致错误拒绝，其无效结果保留在 `results_adapter_v0`，不纳入成绩。修复只改变归档消息和空ID关联，模型与规则未改。修正后两版正式回放无检测器错误、无未知工具、无归档错误。调用ID缺失时用真实 `tool_call` 的函数和参数唯一关联，不推测或编造动作。

## 三、真实接口及新增机制

真实 Docker 接口完成两项批准查询，匿名访问401、错误主体403、请求内伪造步骤403。固定计划中的数据来源和控制参数严格分离，返回中的伪造权限声明不能增加步骤或修改收件人。105个不同归档攻击载荷代入一个合成固定工作流后，工具步骤和批准目的地均保持不变；这是固定计划结构不变量验证，未运行生成模型、真实邮件或完整外部任务，不算105次真实攻击阻断，也不保证摘要内容正确。

非空业务账本专项共480次决策：240次直接/编码/片段外泄均拒绝，240次明确释放给指定目的地的发送均放行。12个来源在重新打开持久化账本后恢复。最大决策耗时3.01ms以内。来源标签单调累加，跨主体读取必须有实际返回，链路图包括真实读取步骤。该专项是合成测试，不能计入外部泛化检出率。

官方运行期45条图见证、22次结果干预已重放复验，源提示词、原生栈、调用链及决策证书保留。本轮官方结果没有新增语义拒绝，故官方审计不能证明新模型有效；外部轨迹出现386次结果拒绝，语义效果须看外部结果与公开文本测试。

## 四、性能与复现限制

CPU 指标使用同一容器、同一PID、原始完整5,200事件，baseline/guard对照，统计原生应用增量、框架守卫、栈侧车及保守空闲成本。完整模块下初版8.98%，实际长度版本6.08%，因此资源门槛仍不满足。不得通过关闭语义模块、抽掉证据或减少攻击样本来把完整R10描述成通过5%。两轮版本不同，不能合并成重复实验置信区间。第二轮guard有158个延迟事件，不能将40 offered events/s说成稳定40完成任务/s。

官方负载中新增业务账本记录0个普通敏感来源，故该轮CPU不能证明高负载非空业务传播场景的成本。语义缓存上限2048、单次最多8窗口、每窗口最多128token；低重复长文本与冷启动要另行测量。另一次ONNX图融合优化只快约1.5%，未采用，其候选及记录保留。

初次部署构建分支补上原生R10镜像构建，测量使用的 `--no-build` 路径未改变。确切测量脚本字节保存在 `R10_cpu_optimized/driver_snapshot`，构建差异见 `build_fix_note.json`。生产已退出benchmark模式，模型摘要、官方源文件、私有状态命名空间及侧车重加入均复验。

## 五、仍需解决的缺口

1. 外部拦截机会仅30.79%，还有254条历史成功攻击未拒绝；banking112、slack69、travel46、workspace27。下一版应先按攻击目标区分越权动作、外泄、写入污染与输出内容篡改，再建立真实主体/对象/用途授权。
2. 两次外部正常误拒绝均来自继承的高后果分类：读取用户信用卡信息被错当作金融交易。需要依据可信实现和接口的读写副作用重建元数据，避免只由描述里的金融名词决定动作类别。本轮保留失败，未把已使用的外部数据重新称为盲测。
3. MiniLM分类头仍漏报较多，且文本标签缺少原始任务上下文。后续应采用含可信任务、工具契约与来源的情境模型，并检验多段文本弱监督，不能靠下调阈值承诺95%。
4. 固定计划模式尚未覆盖任意自由文本自动规划；当前仅两项正式只读计划。未配置生成模型服务，未开展真实模型闭环任务成功率或攻击成功率测量。历史回放和确定性stub不能替代这些证据。
5. CPU仍需至少降低1.09个百分点并开展反向顺序重复对照；保留完整采集和正常任务完成度。扩展标签和主体传播时需另测非空账本资源、压缩/加密/改写泄漏与容量耗尽。

技术细节见 `R10_技术说明书.md`；机器汇总为 `qualification_summary_r10.json`。原R8、R9.1目录及桌面ZIP保留，交付不包含私有SQLite、令牌或生产可写状态。
'''
(ROOT/'01_交付文档/R10_增强作品与检测报告.md').write_text(report,encoding='utf-8')
print(json.dumps({'tests':126,'external_verified_opportunities':b['validated_interception'],'external_successful_traces':b['n'],'cpu_percent':cpu['max'],'fully_qualified':False}))
