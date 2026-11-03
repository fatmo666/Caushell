import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from caushell_tb.bridge import ExternalEngine

class BridgeTests(unittest.TestCase):
    def test_cleanup_distinguishes_prior_sigkill_from_forced_shutdown(self):
        class Journal:
            def __init__(self):self.rows=[]
            def emit(self,kind,**data):self.rows.append((kind,data))
        class Process:
            def __init__(self,pid,code,force=False):
                self.pid,self.returncode,self.force=pid,code,force
                self.stdin,self.stdout=io.BytesIO(),io.BytesIO()
                self.killed=False
            def poll(self):return self.returncode
            def wait(self,timeout):
                if self.force and not self.killed:raise subprocess.TimeoutExpired('fixture',timeout)
                return self.returncode
            def terminate(self):pass
            def kill(self):self.killed=True;self.returncode=-9
        for forced in [False,True]:
            with self.subTest(forced_by_cleanup=forced):
                engine=ExternalEngine.__new__(ExternalEngine)
                engine.closed=False;engine.failed=None;engine.parent=None;engine.thread=None
                engine.process=Process(101,None if forced else -9,forced)
                engine.observer=Process(102,0)
                engine.observer_reader,engine.stderr,engine.observer_stderr=io.BytesIO(),io.BytesIO(),io.BytesIO()
                engine.journal=Journal()
                with self.assertRaisesRegex(RuntimeError,'transport exit -9'):engine.close()
                exits=[row for kind,row in engine.journal.rows if kind=='observation_transport_process_exit']
                self.assertEqual([r['role'] for r in exits],['guard','observer'])
                self.assertEqual(exits[0],dict(role='guard',pid=101,returncode=-9,
                    already_exited=not forced,forced_by_cleanup=forced))
                self.assertEqual(exits[1]['returncode'],0)
                self.assertTrue(engine.stderr.closed)

    def test_native_inventory_is_explicit_private_and_does_not_authorize(self):
        engine=ExternalEngine.__new__(ExternalEngine);engine.rpc_lock=threading.RLock();engine.home='/home/user';engine.workspace='/app'
        engine.plan=lambda *args,**kwargs:dict(requirements=dict(environment_names=[]))
        requests=[]
        engine.call=lambda request,tool_id:requests.append(request) or dict(decision='need_approval')
        inventory={'date':'gnu_coreutils'}
        response=engine.check_observed('echo $((x))','/app','s','e','n',b'',[],lambda *args:dict(environment=[]),'tool',native_variants=inventory)
        self.assertEqual(response['decision'],'need_approval')
        frame=requests[0]['payload']['shell_state_before']['execution_frame']
        self.assertEqual(frame['native_variants'],inventory)
        inventory.clear()
        self.assertEqual(frame['native_variants'],{'date':'gnu_coreutils'})

    def test_cross_request_reply_closes_guard_channel(self):
        class Journal:
            def emit(self,*args,**kwargs):pass
        class Observer:
            stdin=io.BytesIO()
            def poll(self):return None
        engine=ExternalEngine.__new__(ExternalEngine);engine.observer_lock=threading.Lock();engine.parent,client=socket.socketpair();engine.failed=None;engine.journal=Journal();engine.observer=Observer()
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
