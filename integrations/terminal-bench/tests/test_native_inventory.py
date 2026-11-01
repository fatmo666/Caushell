"""Private inert deployment fixtures; no task program or model is executed."""
import copy
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from caushell_tb.native_inventory import validate, verified_variants, LOADER_NAMES
from caushell_tb.bridge import ExternalEngine
from caushell_tb import owned_frames
spec=importlib.util.spec_from_file_location('frame_test_support',ROOT.parent/'execution-frame'/'test_observation.py')
support=importlib.util.module_from_spec(spec);sys.path.insert(0,str(ROOT.parent/'execution-frame'));spec.loader.exec_module(support)
protocol=owned_frames.protocol
IMAGE='sha256:'+'a'*64

def inventory():
    return dict(schema=1,image_id=IMAGE,commands={'clock':dict(variant='gnu_coreutils',executable='/sealed/clock',closed_runtime=True,files={'/sealed/clock':dict(size=9,sha256='b'*64)})})

class NativeInventoryTests(unittest.TestCase):
    def test_manifest_requires_bounded_explicit_image_and_loading_attestation(self):
        self.assertEqual(validate(inventory(),IMAGE),inventory())
        for mutate in [lambda v:v.update(image_id='sha256:'+'c'*64),lambda v:v['commands']['clock'].update(closed_runtime=False),lambda v:v['commands']['clock']['files'].update({'/sealed/../escape':dict(size=0,sha256='a'*64)}),lambda v:v['commands']['clock']['files']['/sealed/clock'].update(size=16*1024*1024+1)]:
            v=inventory();mutate(v)
            with self.assertRaises(ValueError):validate(v,IMAGE)

    def test_closed_pins_are_facts_and_missing_loader_or_file_proof_stays_unknown(self):
        frame=dict(environment=[dict(name=n,value=dict(status='absent')) for n in LOADER_NAMES])
        lookups={'clock':dict(kind='file',path='/sealed/clock')}
        observed=dict(executable=True,content=dict(source='current_process',status='complete',path='/sealed/clock',sha256='b'*64,bytes_observed=9,identity=dict(size=9)))
        self.assertEqual(verified_variants(inventory(),frame,lookups,lambda p:observed),{'clock':'gnu_coreutils'})
        for bad in [dict(observed,executable=False),dict(observed,content=dict(observed['content'],status='changed')),dict(observed,content=dict(observed['content'],sha256='d'*64)),None,dict(observed,content=None),dict(observed,content=dict(observed['content'],identity=None))]:
            self.assertEqual(verified_variants(inventory(),frame,lookups,lambda p:bad),{})
        self.assertEqual(verified_variants(inventory(),dict(environment=[]),lookups,lambda p:observed),{})
        frame['environment'][0]['value']=dict(status='present',value='loader.so')
        self.assertEqual(verified_variants(inventory(),frame,lookups,lambda p:observed),{})
        self.assertEqual(verified_variants(inventory(),frame,{'clock':dict(kind='file',path='/different')},lambda p:observed),{})

    def capture(self,setup,names):
        p=support.plan([]);p['requirements']['native_command_names']=list(names)
        script='builtin source '+shlex.quote(str(ROOT.parent/'execution-frame'/'capture.bash'))+'\n'+setup+'\ncaushell_frame_capture_extended "$@"'
        raw=subprocess.check_output(['/bin/bash','--noprofile','--norc','-c',script,'owner','0'*32,'0','0',str(len(names)),*names],env={'PATH':'/usr/bin:/bin'})
        return protocol.decode(p,'0'*32,raw),raw,p

    def test_owning_builtin_lookup_never_executes_and_shadowed_or_relative_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            exe=Path(d)/'clock';exe.write_text('must not be executed');exe.chmod(0o700)
            frame,raw,p=self.capture('PATH='+shlex.quote(d),('clock',))
            self.assertEqual(frame['_native_executables']['clock'],dict(kind='file',path=str(exe)))
            for setup in ['clock(){ :; }; PATH='+shlex.quote(d),'shopt -s expand_aliases; alias clock=anything; PATH='+shlex.quote(d),'PATH=.']:
                f,_,_=self.capture(setup,('clock',))
                self.assertEqual(f['_native_executables']['clock'],dict(kind='unavailable',path=''))
            with self.assertRaises(ValueError):protocol.decode(p,'0'*32,raw[:-4])
            with self.assertRaises(ValueError):protocol.decode(p,'1'*32,raw)

    def test_public_collection_keeps_native_and_scalar_channels_separate(self):
        p=support.plan(list(LOADER_NAMES));p['requirements'].update(variable_names=['LOCAL'],native_command_names=['printf','bash'])
        with tempfile.TemporaryDirectory() as d:
            owner=support.PausedBash(d,d,'LOCAL=private; export -n LOCAL')
            try:frame=protocol.collect(p,owner.capture)
            finally:owner.close()
        self.assertEqual(frame['variables'],[dict(name='LOCAL',value=dict(status='present',value='private'))])
        self.assertEqual(frame['_native_executables']['printf']['kind'],'unavailable')
        self.assertEqual(frame['_native_executables']['bash']['kind'],'file')

    def test_bridge_supplies_only_verified_facts_and_retains_original_decision(self):
        engine=ExternalEngine.__new__(ExternalEngine);engine.rpc_lock=threading.RLock();engine.home='/home/u';engine.workspace='/app';engine.native_inventory=inventory()
        class Journal:
            def emit(self,*args,**kwargs):pass
        engine.journal=Journal();requests=[]
        def call(request,tool_use_id=None):
            if request['kind']=='execution_frame_plan':return dict(requirements=dict(environment_names=[],variable_names=[],pathname=False))
            requests.append(request);return dict(decision='deny')
        engine.call=call
        p=engine.plan('rm -rf /','/app','s','e')
        self.assertEqual(p['requirements']['native_command_names'],['clock'])
        self.assertTrue(set(LOADER_NAMES)<=set(p['requirements']['environment_names']))
        frame=dict(environment=[],_native_executables={'clock':dict(kind='file',path='/sealed/clock')})
        with patch('caushell_tb.bridge.verified_variants',return_value={'clock':'gnu_coreutils'}) as verify:
            engine._native_file=lambda p:{}
            r=engine.check_observed('rm -rf /','/app','s','e','n',b'',p['requirements']['environment_names'],lambda *a:copy.deepcopy(frame),'t')
        self.assertEqual(r['decision'],'deny');self.assertEqual(verify.call_count,1)
        observation=requests[0]['payload']['shell_state_before']['execution_frame']
        self.assertEqual(observation['native_variants'],{'clock':'gnu_coreutils'})
        self.assertNotIn('_native_executables',observation)
        self.assertNotIn('grant',json.dumps(requests))

if __name__=='__main__':unittest.main()
