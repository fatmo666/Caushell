import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from caushell_tb.contract import prepare_task,manifest,overlay,validate_overlay,task_users,validate_container,admit_model,sha,save,validate_native_client
from caushell_tb.bridge import exec_prefix,line

class ContractTests(unittest.TestCase):
    def test_task_is_byte_identical_including_omitted_defaults_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);src=root/'source';src.mkdir()
            config=b'# Keep original defaults.\n[agent]\ntimeout_sec=900\n[verifier]\nenvironment_mode="separate"\nuser="checker"\n[environment]\nworkdir="/work"\n'
            (src/'task.toml').write_bytes(config);(src/'tests').mkdir();(src/'tests/test.sh').write_text('exit 0\n');(src/'linked').symlink_to('tests/test.sh')
            os.chmod(src/'tests/test.sh',0o751)
            prepare_task(src,root/'copy',root/'record.json')
            self.assertEqual(manifest(src),manifest(root/'copy'))
            self.assertEqual((root/'copy/task.toml').read_bytes(),config)
            self.assertFalse(json.loads((root/'record.json').read_text())['semantic_overrides'])

    def test_inherited_and_explicit_users_remain_distinct(self):
        self.assertEqual(task_users({},dict(Config=dict(User='1001'))),dict(image_user='1001',agent_user=None,verifier_user=None,verifier_environment_mode=None))
        self.assertEqual(task_users(dict(agent=dict(user='worker'),verifier=dict(user='root',environment_mode='separate')),dict(Config={})),dict(image_user='',agent_user='worker',verifier_user='root',verifier_environment_mode='separate'))
        base=exec_prefix('docker','a'*64)
        self.assertNotIn('--user',base)
        self.assertIn('worker',exec_prefix('docker','a'*64,'worker','/work'))
        with self.assertRaises(ValueError):exec_prefix('docker','short')

    def test_overlay_rejects_silent_task_semantic_changes(self):
        with tempfile.TemporaryDirectory() as root:
            good=overlay(root,'/tmp/.caushell-harness-test','sha256:'+'a'*64,'owner')
            self.assertEqual(validate_overlay(good),good)
            for key,value in [('user','bench'),('security_opt',['no-new-privileges']),('environment',{'PATH':'/foreign'}),('working_dir','/different'),('command','sleep infinity')]:
                bad=copy.deepcopy(good);bad['services']['main'][key]=value
                with self.assertRaises(ValueError):validate_overlay(bad)
            bad=copy.deepcopy(good);bad['services']['main']['volumes'][0]['read_only']=False
            with self.assertRaises(ValueError):validate_overlay(bad)

    def test_privilege_or_evidence_exposure_is_rejected_without_rewriting_it(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);assets=root/'assets';assets.mkdir();evidence=root/'evidence';mount='/tmp/.caushell-harness-test'
            good=dict(Image='sha256:fixed',HostConfig={},Mounts=[dict(Source=str(assets),Destination=mount,RW=False)])
            validate_container(good,good['Image'],assets,mount,evidence)
            for host in [dict(Privileged=True),dict(CapAdd=['CAP_SYS_PTRACE']),dict(CapAdd=['SYS_ADMIN'])]:
                bad=copy.deepcopy(good);bad['HostConfig']=host
                with self.assertRaises(ValueError):validate_container(bad,good['Image'],assets,mount,evidence)
            for item in [dict(Source=str(root),Destination='/all-evidence',RW=False),dict(Source='/var/run/docker.sock',Destination='/var/run/docker.sock',RW=True)]:
                bad=copy.deepcopy(good);bad['Mounts'].append(item)
                with self.assertRaises(ValueError):validate_container(bad,good['Image'],assets,mount,evidence)

    def test_inference_admission_rejects_missing_failed_and_stale_bootstrap(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);plan=root/'plan.json';save(plan,{'mode':'local'});values=dict(mode='local',local_model_launch_authorized=True)
            with self.assertRaises(ValueError):admit_model(values,plan)
            (root/'preflight').mkdir();status=root/'preflight/acceptance.json'
            for verified,digest in [(False,sha(plan)),(True,'outdated')]:
                status.write_text(json.dumps(dict(verified=verified,plan_sha256=digest)))
                with self.assertRaises(ValueError):admit_model(values,plan)
            status.write_text(json.dumps(dict(verified=True,plan_sha256=sha(plan))))
            admit_model(values,plan)
            with self.assertRaises(ValueError):admit_model(dict(values,local_model_launch_authorized=False),plan)

    def test_private_framing_rejects_eof_and_oversize(self):
        import socket
        for raw in [b'',b'{}',b'['+b'x'*(2*1024*1024)+b'\n']:
            a,b=socket.socketpair()
            def send():
                try:b.sendall(raw)
                except BrokenPipeError:pass
                finally:b.close()
            import threading
            t=threading.Thread(target=send);t.start()
            with a.makefile('rb') as reader:
                with self.assertRaises(ValueError):line(reader)
            a.close();t.join()

    def test_partial_open_observer_frame_has_a_deadline(self):
        import socket
        a,b=socket.socketpair();b.sendall(b'{')
        try:
            with a.makefile('rb') as stream:
                with self.assertRaises(TimeoutError):line(stream,timeout=0.02)
        finally:a.close();b.close()

    def test_client_reexec_requires_matching_architecture_and_direct_entry(self):
        with tempfile.TemporaryDirectory() as root:
            header=bytearray(20);header[:6]=b'\x7fELF\x02\x01';header[18:20]=(183).to_bytes(2,'little');(Path(root)/'claude').write_bytes(header)
            native=dict(claude=['{assets}/claude'])
            validate_native_client(root,dict(Architecture='arm64'),native)
            with self.assertRaises(ValueError):validate_native_client(root,dict(Architecture='amd64'),native)
            with self.assertRaises(ValueError):validate_native_client(root,dict(Architecture='arm64'),dict(claude=['{assets}/ld.so','{assets}/claude']))

if __name__=='__main__':unittest.main()
