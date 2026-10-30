"""Explicit opt-in container integration test; no inference endpoint or model."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from caushell_tb.bridge import ExternalEngine
from caushell_tb.journal import BufferedJournal
from caushell_tb.contract import save


def main():
    p=argparse.ArgumentParser();p.add_argument('plan',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    c=json.loads(a.plan.read_text());a.output.mkdir();docker=c['docker'];container=None;engine=None
    journal=BufferedJournal(a.output/'events.jsonl',dict(kind='offline_namespace_regression'))
    def call(*args):return subprocess.run([docker,*args],text=True,capture_output=True,check=True)
    try:
        container=call('run','--detach','--label','org.caushell.rq3.envfix.owner=rq3-envfix-20261031-v1','--mount',f'type=bind,src={c["assets"]},dst={c["asset_mount"]},readonly',c['image_id'],'sleep','infinity').stdout.strip()
        call('exec',container,'bash','-c',"printf '#!/bin/bash\\nprintf namespace-observed\\n' > /app/namespace-only.sh; ln -s /etc/passwd /app/observed-link")
        commands=[x.replace('{assets}',c['asset_mount']) for x in c['commands']['observer']]
        engine=ExternalEngine(docker,container,None,commands,c['host_guard'],c['guard_config'],a.output,journal,'/root','/app')
        decisions={}
        for name,cmd in [('script-observation','bash /app/namespace-only.sh'),('inline-ask','python -c "print(1)"'),('deletion-ask','rm /app/ordinary'),('hard-deny','rm -rf /')]:
            result=engine.check(cmd,'/app','namespace-regression');save(a.output/(name+'.json'),result);decisions[name]=result['decision']
        trace=json.loads((a.output/'script-observation.json').read_text())['decision_trace']
        targets=trace['path_targets']
        assert any(o['source']=='supplied_view' and o['path']=='/app/namespace-only.sh' and o['entry']['kind']=='file' for t in targets for o in t['observations'])
        pid=engine.identity['pid']
        read= subprocess.run([docker,'exec',container,'bash','-c',f'timeout 1 cat /proc/{pid}/fd/0'],text=True,capture_output=True)
        asset_write=subprocess.run([docker,'exec',container,'bash','-c',f'printf corrupt > {c["asset_mount"]}/observer'],text=True,capture_output=True)
        save(a.output/'root-tamper-probes.json',dict(private_fd=dict(exit_code=read.returncode,stderr=read.stderr),immutable_assets=dict(exit_code=asset_write.returncode,stderr=asset_write.stderr)))
        assert read.returncode!=0 and 'Permission denied' in read.stderr,read
        assert asset_write.returncode!=0 and 'Read-only file system' in asset_write.stderr,asset_write
        assert decisions=={'script-observation':'allow','inline-ask':'need_approval','deletion-ask':'need_approval','hard-deny':'deny'},decisions
        engine.observer.stdin.close();engine.observer.wait(timeout=5)
        try:engine.check('cat /app/namespace-only.sh','/app','channel-death')
        except (RuntimeError,EOFError,TimeoutError):pass
        else:raise AssertionError('Lost observer must not silently allow')
        save(a.output/'acceptance.json',dict(verified=True,decisions=decisions,root_cannot_open_private_observer_fd=True,assets_immutable=True,channel_loss_fails_closed=True,real_model_requests=0))
    finally:
        try:
            if engine:engine.close(raise_errors=False)
        finally:
            if container:call('rm','--force',container)
            journal.close()

if __name__=='__main__':main()
