#!/usr/bin/env python3
"""Launch only a previously prepared, immutable task-faithful plan."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import sys


def main():
    p=argparse.ArgumentParser();p.add_argument('plan',type=Path);p.add_argument('--preflight',action='store_true');args=p.parse_args()
    plan=json.loads(args.plan.read_text());root=args.plan.resolve().parent
    # Explicit dependency on the pinned RQ3 telemetry/protocol package, not an
    # import from a mutable old run's common.py or agent.py.
    sys.path.insert(0,plan['runtime_root']);sys.path.insert(0,str(Path(__file__).resolve().parent))
    from caushell_tb.contract import sha,save,verify_plan,admit_model
    verify_plan(plan)
    if args.preflight:
        preflight=root/'preflight';preflight.mkdir(exist_ok=False)
        clone=dict(plan,mode='offline',fixture_steps=[],model='fixture-model',local_model_launch_authorized=False,host_workdir=str(preflight),outputs=str(preflight/'outputs'),trial=plan['trial']+'-bootstrap')
        (preflight/'outputs').mkdir();save(preflight/'plan.json',clone)
        import subprocess
        process=subprocess.run([sys.executable,'-B',__file__,str(preflight/'plan.json')])
        returned=preflight/'returned-result.json';report=preflight/'outputs'/clone['trial']/'verifier/ctrf.json'
        # Standard TB pytest tasks: collect real tests, even if expected outputs
        # are absent in this zero-agent clone. A bootstrap/network failure is not ready.
        ready=False
        if process.returncode==0 and returned.exists() and not json.loads(returned.read_text()).get('exception_info') and report.exists():
            value=json.loads(report.read_text());ready=bool(value.get('results',{}).get('tests'))
        save(preflight/'acceptance.json',dict(verified=ready,plan_sha256=sha(args.plan),real_model_requests=0,synthetic_model_used=True,original_task_unchanged=True,ctrf=str(report),exit_code=process.returncode))
        if not ready:raise RuntimeError('Verifier preflight failed; model execution remains disabled. Inspect preserved bootstrap logs.')
        return
    admit_model(plan,args.plan)
    if (root/'launch.json').exists():raise FileExistsError('Run plans cannot be replayed')
    os.environ.pop('CLAUDECODE',None)
    from harbor.models.trial.config import TrialConfig
    from harbor.trial.trial import Trial
    async def run():
        config=TrialConfig.model_validate(dict(task=dict(path=plan['task']),trial_name=plan['trial'],trials_dir=plan['outputs'],environment=dict(type='docker',delete=True,extra_docker_compose=[plan['compose']]),agent=dict(import_path='caushell_tb.harbor_agent:TaskFaithfulClaude',model_name=plan['model'],skip_model_parsing=True,env=dict(ANTHROPIC_API_KEY='engineering-dummy-key'),kwargs=dict(faithful_config=str(args.plan.resolve()))),verifier=dict(disable=False)))
        save(root/'launch.json',dict(config=config.model_dump(mode='json'),task_semantic_overrides={},mode=plan['mode']))
        trial=await Trial.create(config);result=await trial.run();save(root/'returned-result.json',result.model_dump(mode='json'))
        print(json.dumps(dict(trial=plan['trial'],reward=result.verifier_result.rewards if result.verifier_result else None,exception=result.exception_info.model_dump(mode='json') if result.exception_info else None)))
        return result
    result=asyncio.run(run())
    from caushell_tb.verification import inspect_verifier
    validation=inspect_verifier(Path(plan['outputs'])/plan['trial'],result.verifier_result.rewards if result.verifier_result else None)
    save(root/'verifier-validation.json',validation)
    if not validation['verified']:raise SystemExit(2)
    if result.exception_info:raise SystemExit(1)

if __name__=='__main__':main()
