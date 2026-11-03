#!/usr/bin/env python3
"""Prepare a new run without changing any upstream task file or semantic field."""
import argparse
import json
import os
from pathlib import Path
import sys
import tomllib
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parent))
from caushell_tb.contract import prepare_task,manifest,save,sha,overlay,validate_overlay,task_users,validate_native_client,inspect_image_configuration


from caushell_tb.native_inventory import load as load_native_inventory

def main():
    p=argparse.ArgumentParser()
    for name in ['source','output','assets','runtime-root','host-guard','guard-config']:p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--docker',default='/Users/huangyu/.docker/bin/docker');p.add_argument('--mode',choices=['offline','local'],default='offline')
    p.add_argument('--image-platform',choices=['linux/amd64','linux/arm64'],default='linux/amd64')
    p.add_argument('--image-id',help='Trusted controller-pinned platform manifest SHA; original task reference stays recorded')
    p.add_argument('--legacy-hooks',action='store_true',help='Keep observations unknown when no owning executor transport is supplied')
    p.add_argument('--native-inventory',type=Path,help='Trusted closed-runtime deployment attestation, bound to the exact image')
    p.add_argument('--steps',type=Path);p.add_argument('--provider',type=Path);p.add_argument('--system-prompt',type=Path,required=True);p.add_argument('--authorize-local',action='store_true')
    a=p.parse_args();source=a.source.resolve();output=a.output.resolve();assets=a.assets.resolve();runtime=a.runtime_root.resolve()
    config=tomllib.loads((source/'task.toml').read_text());reference=config['environment'].get('docker_image')
    if not reference:raise ValueError('Resolve an immutable upstream Dockerfile build before preparing model execution; task source must remain unchanged')
    # An unavailable image fails before inference; no pull/retry is hidden here.
    selected=a.image_id or reference
    if a.image_id and (not a.image_id.startswith('sha256:') or len(a.image_id)!=71):raise ValueError('Immutable image identity required')
    image=inspect_image_configuration(a.docker,selected,a.image_platform)
    if a.image_id and image['Id']!=a.image_id:raise ValueError('Pinned platform image identity changed')
    if a.mode=='local' and (not a.authorize_local or not a.provider):raise ValueError('Explicit local-provider launch authorization/configuration required')
    if output.exists():raise FileExistsError(output)
    output.mkdir(parents=True)
    save(output/'image-configuration.json',image)
    task=prepare_task(source,output/'task',output/'task-contract.json')
    owner='rq3-faithful-'+uuid.uuid4().hex[:16];mount='/tmp/.caushell-harness-'+uuid.uuid4().hex
    compose=validate_overlay(overlay(assets,mount,image['Id'],owner));save(output/'compose.json',compose)
    layout=json.loads((assets/'layout.json').read_text())
    for command in layout.values():
        executable=assets/command[0].removeprefix('{assets}/')
        if not executable.is_file() or not os.access(executable,os.X_OK):raise ValueError('Harness executable asset has no execute permission: '+str(executable))
    validate_native_client(assets,image,layout)
    for key in ['claude','observer']:
        if not layout[key] or any(not isinstance(x,str) or '\x00' in x for x in layout[key]):raise ValueError('Invalid executable asset command')
        if not layout[key][0].startswith('{assets}/'):raise ValueError('Executable must come from immutable harness assets')
    frame_root=Path(__file__).resolve().parent.parent/'execution-frame'
    frame_files={name:sha(frame_root/name) for name in ['observation.py','capture.bash']}
    if not a.legacy_hooks:
        for name,expected in [('capture.bash',frame_files['capture.bash']),('owning-frame.bash',sha(Path(__file__).resolve().parent/'owning-frame.bash'))]:
            if not (assets/name).is_file() or sha(assets/name)!=expected:raise ValueError('Pinned owning-frame helper missing or different: '+name)
    assets_hash={str(p.relative_to(assets)):sha(p) for p in sorted(assets.rglob('*')) if p.is_file()}
    runtime_files={str(p.relative_to(runtime)):sha(p) for p in sorted((runtime/'rq3').glob('*.py'))}
    if not runtime_files:raise ValueError('Pinned RQ3 protocol/telemetry dependency missing')
    (output/'outputs').mkdir();users=task_users(config,image)
    integration=Path(__file__).resolve().parent
    integration_files={str(p.relative_to(integration)):sha(p) for p in sorted(integration.rglob('*.py')) if '__pycache__' not in p.parts and 'tests' not in p.relative_to(integration).parts}
    plan=dict(owning_frames=not a.legacy_hooks,execution_frame_root=str(frame_root),execution_frame_files=frame_files,integration_root=str(integration),integration_files=integration_files,compose_sha256=sha(output/'compose.json'),schema=1,mode=a.mode,task=str(task),task_manifest=manifest(task),task_config_sha256=sha(task/'task.toml'),task_users=users,agent_user=users['agent_user'],image_id=image['Id'],image_reference=reference,image_platform=a.image_platform,image_selection_reference=selected,image_user=users['image_user'],
      runtime_root=str(runtime),runtime_files=runtime_files,assets=str(assets),asset_mount=mount,asset_sha256=assets_hash,asset_manifest=manifest(assets),commands=layout,
      state_dir='/tmp/.caushell-session-'+uuid.uuid4().hex,host_guard=str(a.host_guard.resolve()),host_guard_sha256=sha(a.host_guard),guard_config=str(a.guard_config.resolve()),guard_config_sha256=sha(a.guard_config),
      docker=a.docker,owner=owner,compose=str(output/'compose.json'),outputs=str(output/'outputs'),trial=owner,host_workdir=str(output),
      system_prompt=a.system_prompt.read_text(),agent_timeout=config.get('agent',{}).get('timeout_sec'),local_model_launch_authorized=a.authorize_local,
      fixture_steps=json.loads(a.steps.read_text()) if a.steps else [],model='fixture-model',native_max_tokens=32000)
    if a.native_inventory:
        load_native_inventory(a.native_inventory,image['Id'])
        plan.update(native_inventory_path=str(a.native_inventory.resolve()),native_inventory_sha256=sha(a.native_inventory))
    if a.mode=='local':
        plan['provider']=json.loads(a.provider.read_text());plan['model']=plan['provider']['model']
    save(output/'plan.json',plan)
    print(json.dumps(dict(plan=str(output/'plan.json'),semantic_overrides={},users=users,image_id=image['Id'],model_calls=0)))

if __name__=='__main__':main()
