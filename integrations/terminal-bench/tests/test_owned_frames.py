import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from caushell_tb.owned_frames import OwningFrameLifecycle
from caushell_tb.journal import BufferedJournal

BINARY=os.environ.get('CAUSHELL_TEST_HOST')

class Engine:
    identity={'frame_submit_protocol':1}
    rpc_lock=threading.RLock()
    def __init__(self,decision):self.decision=decision;self.frames=[];self.authorizations=[]
    def plan(self,command,cwd,session,executor):
        return dict(binding=dict(executor_instance_id=executor),requirements=dict(environment_names=['HOME','TEST_VALUE','name','status'],pathname=True))
    def check_observed(self,command,cwd,session,executor,nonce,raw,names,decode,tool_use_id,observed_home=None):
        frame=decode(self.plan(command,cwd,session,executor),nonce,raw);frame['_observed_shell_home']=observed_home;self.frames.append(frame)
        return dict(decision=self.decision,check_receipt=dict(check_id=dict(session_id=session,sequence_no=1),state_revision=1))
    def authorize(self,receipt,approved,tool_use_id):
        self.authorizations.append(approved);return dict(approved=approved,check_id=receipt['check_id'])

@unittest.skipUnless(BINARY,'explicit compiled frame-submit host required')
class OwningFrameTests(unittest.TestCase):
    def trial(self,command,*,prelude='',decision='allow',policy='approve',stdin=None,transport_failure=False):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);integration=Path(__file__).resolve().parents[1]
            for name,source in [('owning-frame.bash',integration/'owning-frame.bash'),('capture.bash',integration.parent/'execution-frame/capture.bash')]:shutil.copy2(source,root/name)
            journal=BufferedJournal(root/'events.jsonl');engine=Engine(decision)
            lifecycle=OwningFrameLifecycle('s',journal,engine,str(root/'owning-frame.bash'),[BINARY],approval_policy=policy,address=('127.0.0.1',0),public_host='127.0.0.1')
            try:
                if transport_failure:lifecycle.frames.endpoint='http://127.0.0.1:1/frame'
                payload=dict(session_id='s',tool_name='Bash',cwd=str(root),tool_input=dict(command=command))
                out=lifecycle.before('tool',payload);ticket=next(iter(lifecycle.frames.pending));nonce=lifecycle.frames.pending[ticket]['nonce'];wrapped=out['hookSpecificOutput']['updatedInput'];self.assertIsNone(lifecycle.actions['tool']['guard'])
                lifecycle.approve('tool','Bash',wrapped);self.assertIsNone(lifecycle.actions['tool']['guard'])
                env=dict(os.environ,TEST_VALUE='original',name='user-name',status='user-status')
                process=subprocess.run(['/bin/bash','--noprofile','--norc','-c',prelude+'\n'+wrapped['command']],cwd=root,env=env,input=stdin,text=True,capture_output=True,timeout=10)
                row=lifecycle.actions['tool'];facts=engine.frames
                if facts:
                    values={v['name']:v['value'] for v in facts[0]['environment']}
                    self.assertEqual(values['TEST_VALUE'],dict(status='present',value='original'))
                    self.assertEqual(values['name']['value'],'user-name');self.assertEqual(values['status']['value'],'user-status')
                lifecycle.after('tool',dict(payload,tool_input=wrapped,error=process.stderr),failed=process.returncode!=0)
                with self.assertRaises(ValueError):lifecycle.frames.accept(dict(ticket=ticket,nonce=nonce,cwd=str(root),raw=[]))
                marker=(root/'marker').exists()
                # The gate is consumed exactly once, independent of later native results.
                self.assertEqual(len(lifecycle.frames.pending),0)
                return process,row,facts,engine.authorizations,marker
            finally:lifecycle.close();journal.close()

    def test_real_owner_captures_shell_options_and_preserves_status(self):
        p,row,facts,_,_=self.trial('printf "%s|%s|%s" "$?" "$name" "$status"',prelude='set -f; shopt -s nullglob; (exit 7)')
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(p.stdout,'7|user-name|user-status')
        self.assertTrue(facts[0]['pathname']['noglob']);self.assertTrue(facts[0]['pathname']['nullglob'])
        self.assertEqual(row['guard']['decision'],'allow')

    def test_stdin_and_errexit_are_not_consumed_or_disabled(self):
        p,*_=self.trial('read -r value; printf "%s" "$value"',stdin='unchanged-input\n');self.assertEqual(p.stdout,'unchanged-input',p.stderr)
        p,*_=self.trial('false; printf should-not-run',prelude='set -e');self.assertEqual(p.returncode,1,p.stderr);self.assertNotIn('should-not-run',p.stdout)

    def test_deny_and_declined_ask_cannot_execute_the_pending_action(self):
        for decision,policy in [('deny','approve'),('need_approval','reject')]:
            p,row,_,approved,marker=self.trial('touch marker',decision=decision,policy=policy)
            self.assertNotEqual(p.returncode,0);self.assertFalse(marker)
            self.assertEqual(row['status'],'denied' if decision=='deny' else 'rejected')
            self.assertEqual(approved,[] if decision=='deny' else [False])

    def test_known_frame_facts_do_not_grant_resource_authority(self):
        p,row,facts,approved,marker=self.trial('touch marker',decision='need_approval')
        self.assertEqual(p.returncode,0,p.stderr);self.assertTrue(marker);self.assertTrue(facts)
        self.assertEqual(row['guard']['decision'],'need_approval');self.assertEqual(approved,[True]);self.assertTrue(row['approval']['executor_callback'])

    def test_transport_loss_never_executes_the_pending_body(self):
        p,row,facts,approved,marker=self.trial('touch marker',transport_failure=True)
        self.assertNotEqual(p.returncode,0);self.assertFalse(marker);self.assertFalse(facts);self.assertFalse(approved)
        self.assertEqual(row['status'],'executor_gate_failed')

    def test_shell_home_is_observed_separately_from_child_environment(self):
        p,row,facts,_,_=self.trial('printf ok',prelude='HOME=/opt; export -n HOME')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(facts[0]['_observed_shell_home'],'/opt')
        values={v['name']:v['value'] for v in facts[0]['environment']}
        self.assertEqual(values['HOME'],dict(status='absent'))

    def test_early_background_callback_cannot_run_real_bash_before_check_and_approval(self):
        for order in ('before_frame','during_check'):
            for decision,policy in [('allow','approve'),('need_approval','approve'),
                                    ('deny','approve'),('need_approval','reject')]:
                with self.subTest(order=order,decision=decision,policy=policy), tempfile.TemporaryDirectory() as tmp:
                    root=Path(tmp);integration=Path(__file__).resolve().parents[1]
                    for name,source in [('owning-frame.bash',integration/'owning-frame.bash'),('capture.bash',integration.parent/'execution-frame/capture.bash')]:shutil.copy2(source,root/name)
                    check_entered,check_release=threading.Event(),threading.Event()
                    approval_entered,approval_release=threading.Event(),threading.Event()
                    class PausedEngine(Engine):
                        def check_observed(self,*args,**kwargs):
                            check_entered.set()
                            if not check_release.wait(5):raise TimeoutError('Check fixture not released')
                            return super().check_observed(*args,**kwargs)
                        def authorize(self,*args,**kwargs):
                            approval_entered.set()
                            if not approval_release.wait(5):raise TimeoutError('Approval fixture not released')
                            return super().authorize(*args,**kwargs)
                    journal=BufferedJournal(root/'events.jsonl');engine=PausedEngine(decision)
                    life=OwningFrameLifecycle('s',journal,engine,str(root/'owning-frame.bash'),[BINARY],approval_policy=policy,address=('127.0.0.1',0),public_host='127.0.0.1')
                    process=None
                    try:
                        payload=dict(session_id='s',tool_name='Bash',cwd=str(root),tool_input=dict(command='printf authorized > marker',run_in_background=True))
                        wrapped=life.before('tool',payload)['hookSpecificOutput']['updatedInput']
                        life.approve('tool','Bash',wrapped)
                        post=dict(payload,tool_input=wrapped,tool_response=dict(backgroundTaskId='bg-tool'))
                        if order=='before_frame':life.after('tool',post)
                        process=subprocess.Popen(['/bin/bash','--noprofile','--norc','-c',wrapped['command']],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                        self.assertTrue(check_entered.wait(3))
                        if order=='during_check':life.after('tool',post)
                        self.assertFalse((root/'marker').exists())
                        self.assertFalse(engine.authorizations)
                        check_release.set()
                        if decision=='need_approval':
                            self.assertTrue(approval_entered.wait(3))
                            self.assertFalse((root/'marker').exists())
                            approval_release.set()
                        out,err=process.communicate(timeout=5)
                        allowed=decision=='allow' or (decision=='need_approval' and policy=='approve')
                        self.assertEqual(process.returncode==0,allowed,err)
                        self.assertEqual((root/'marker').exists(),allowed)
                        life.observe_native(dict(type='system',subtype='task_notification',session_id='s',tool_use_id='tool',task_id='bg-tool',status='completed' if allowed else 'failed'))
                        self.assertEqual(life.actions['tool']['status'],'executed' if allowed else 'denied' if decision=='deny' else 'rejected')
                    finally:
                        check_release.set();approval_release.set()
                        if process and process.poll() is None:process.kill();process.communicate(timeout=3)
                        life.close();journal.close()

if __name__=='__main__':unittest.main()
