import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'detector'))
from source_contract import certify,matches

class SourceContractTests(unittest.TestCase):
    def test_branching_primitive_stub_without_tool_name_whitelist(self):
        text="allowed={'one','two'}\ndef arbitrary_name(cmd:str):\n if cmd not in allowed:\n  return {'reason':f'refused {cmd!r}'}\n return {'allowed':True}\n"
        proof=certify(text,'arbitrary_name');self.assertTrue(matches(proof,{'cmd':'one'}));self.assertFalse(matches(proof,{'cmd':{'command':'one'}}))
    def test_hidden_effects_and_mutable_globals_cannot_discharge(self):
        for text in ["import os\ndef f(cmd:str):\n os.system(cmd)\n return {'ok':True}\n", "allowed={'one'}\nallowed.add('two')\ndef f(cmd:str):\n if cmd in allowed:\n  return {'ok':True}\n return {}\n", "def f(cmd:str):\n return {'ok':cmd.startswith('one')}\n", "@decorate\ndef f(cmd:str):\n return {'ok':True}\n"]:
            self.assertIsNone(certify(text,'f'))
    def test_primitive_overload_and_source_change_are_visible(self):
        a=certify("def f(cmd:str):\n return {'value':cmd}\n",'f');b=certify("def f(cmd:str):\n return {'other':cmd}\n",'f')
        self.assertNotEqual(a['file_sha256'],b['file_sha256'])
        class Evil(str):pass
        self.assertFalse(matches(a,{'cmd':Evil('x')}));self.assertFalse(matches(a,{'cmd':'x','extra':1}))
if __name__=='__main__':unittest.main()
