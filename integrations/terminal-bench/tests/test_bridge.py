import io
import json
import os
from pathlib import Path
import socket
import sys
import threading
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from caushell_tb.bridge import ExternalEngine

class BridgeTests(unittest.TestCase):
    def test_cross_request_reply_closes_guard_channel(self):
        class Journal:
            def emit(self,*args,**kwargs):pass
        class Observer:
            stdin=io.BytesIO()
            def poll(self):return None
        engine=ExternalEngine.__new__(ExternalEngine);engine.parent,client=socket.socketpair();engine.failed=None;engine.journal=Journal();engine.observer=Observer()
        r,w=os.pipe();engine.observer_reader=os.fdopen(r,'rb')
        request=dict(id=1,op='entry',path='/app/task',limit=None)
        wrong=dict(request, id=2)
        os.write(w,json.dumps(dict(request=wrong,value=dict(kind='file'))).encode()+b'\n');os.close(w)
        t=threading.Thread(target=engine._observations);t.start()
        client.sendall(json.dumps(request).encode()+b'\n');client.settimeout(2)
        self.assertEqual(client.recv(16),b'')
        t.join(timeout=2);self.assertFalse(t.is_alive())
        self.assertIn('Cross-request',engine.failed)
        engine.parent.close();client.close();engine.observer_reader.close()

    def test_incomplete_capture_discards_facts_without_skipping_the_original_check(self):
        class Journal:
            def emit(self,*args,**kwargs):pass
        import threading
        engine=ExternalEngine.__new__(ExternalEngine);engine.rpc_lock=threading.RLock();engine.home='/home/user';engine.workspace='/app';engine.journal=Journal()
        engine.plan=lambda *args,**kwargs:dict(requirements=dict(environment_names=[]))
        requests=[]
        engine.call=lambda request,tool_id:requests.append(request) or dict(decision='deny')
        def unavailable(*args):raise ValueError('incomplete capture')
        result=engine.check_observed('rm -rf /','/app','session','executor','nonce',b'',[],unavailable,'tool')
        self.assertEqual(result['decision'],'deny')
        self.assertEqual(requests[0]['payload']['command'],'rm -rf /')
        self.assertNotIn('execution_frame',requests[0]['payload']['shell_state_before'])
        self.assertEqual(requests[0]['payload']['shell_state_before']['observability']['variables'],'unknown')
        self.assertIsNone(requests[0]['payload']['home'])

    def test_actual_shell_home_binds_both_plan_and_check_without_granting_authority(self):
        import threading
        engine=ExternalEngine.__new__(ExternalEngine);engine.rpc_lock=threading.RLock();engine.home='/stale/home';engine.workspace='/app'
        plans=[];requests=[]
        engine.plan=lambda *args,**kwargs:plans.append(kwargs) or dict(requirements=dict(environment_names=[]))
        engine.call=lambda request,tool_id:requests.append(request) or dict(decision='need_approval')
        result=engine.check_observed('printf x > ~/file','/app','s','executor','nonce',b'',[],lambda *args:dict(environment=[]),'tool',observed_home='/opt')
        self.assertEqual(result['decision'],'need_approval')
        self.assertEqual(plans,[dict(home='/opt',home_is_actual=True)])
        self.assertEqual(requests[0]['payload']['home'],'/opt')
        self.assertEqual(requests[0]['payload']['workspace_root'],'/app')

if __name__=='__main__':unittest.main()
