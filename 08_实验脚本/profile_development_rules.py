"""Rule profiling on previously used official traces; not a CPU qualification."""
import cProfile,io,json,os,pstats,sys,tempfile,copy
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
EVIDENCE=ROOT.parent/'AgentGuard_全面增强版R10/07_修复验证/R10_cpu_optimized/pair1_guard/evidence'
sys.path[:0]=[str(ROOT/'track2/detector'),str(ROOT/'track2/collector')]
os.environ.update(GUARD_KG='1',GUARD_R8='1',GUARD_R9='1',GUARD_R10='0',INVENTORY_PATH=str(EVIDENCE/'inventory.json'),GUARD_RESULT_POLICY_PATH=str(ROOT/'05_复现脚本/result_policy.official.json'))
import session,rules
from inline_guard import InlineGuard
session.load_tool_meta(EVIDENCE/'inventory.json');session.load_skill_catalog(EVIDENCE/'inventory.json')
sessions=session.build_sessions(session.load_evidence(EVIDENCE))
profile=cProfile.Profile()
with tempfile.TemporaryDirectory(prefix='r11_rule_profile_') as state:
    os.environ['GUARD_GRAPH_STATE_PATH']=str(Path(state)/'graph.sqlite')
    guard=InlineGuard();profile.enable()
    for source in sessions:
        s=guard._session(source.instance_id);s.prompt=source.prompt;s.identity=source.identity;s.skill=source.skill;s.skill_catalog=source.skill_catalog
        for ordinal,call in enumerate(source.calls):
            call_id=f'actual-{ordinal}'
            decision=guard.check_tool_call(s.instance_id,call.server,call.tool,call.arguments,call_id)
            if decision.blocked:break
            guard.observe_tool_result(s.instance_id,call_id,{'jsonrpc':'2.0','id':call_id,'result':call.result},ok=call.ok)
    profile.disable();guard.close();rules.reset_knowledge_graph()
output=ROOT/'07_修复验证/R11_rule_profile';output.mkdir(exist_ok=True)
profile.dump_stats(str(output/'development.prof'))
text=io.StringIO();pstats.Stats(profile,stream=text).strip_dirs().sort_stats('cumtime').print_stats(35)
(output/'top.txt').write_text(text.getvalue(),encoding='utf-8');print(text.getvalue())
