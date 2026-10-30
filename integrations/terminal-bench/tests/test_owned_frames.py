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

if __name__=='__main__':unittest.main()
