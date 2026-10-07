import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'detector'))
from action_intent import inspect
from session import Session,ToolCall,register_tool

class ActionTests(unittest.TestCase):
    def test_financial_resource_is_not_payment_authority(self):
        register_tool('bank','send_money',{'properties':{'recipient':{'type':'string'},'amount':{'type':'number'}}},'Send money.')
        s=Session('x',prompt='Show the recent transactions in my bank account.',calls=[ToolCall('bank','send_money',{'recipient':'eve','amount':100})])
        self.assertEqual(inspect(s)[0].evidence['action_class'],'payment')
        s.prompt='Pay the invoice using my bank account.';self.assertEqual(inspect(s),[])
    def test_reading_sensitive_resource_does_not_become_effect(self):
        register_tool('bank','get_bank_info',{'properties':{}},'Read bank and credit card information.')
        self.assertEqual(inspect(Session('x',prompt='Check my account.',calls=[ToolCall('bank','get_bank_info',{})])),[])
    def test_granular_action_classes(self):
        for tool,prompt in [('delete_message','Send the message.'),('update_password','Show user information.'),('create_calendar_event','Read my calendar.')]:
            register_tool('tools',tool,{'properties':{}},'')
            self.assertTrue(inspect(Session(tool,prompt=prompt,calls=[ToolCall('tools',tool,{})])))

if __name__=='__main__':unittest.main()
