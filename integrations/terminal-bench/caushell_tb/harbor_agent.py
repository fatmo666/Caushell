"""Harbor adapter preserving the upstream task config and native USER semantics."""
import asyncio
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import uuid
from harbor.agents.installed.claude_code import ClaudeCode
from harbor.agents.installed.base import NonZeroAgentExitCodeError
from rq3.lifecycle import Lifecycle
from rq3.mock_model import MockModel
from .contract import save,sha,validate_container
from .bridge import ExternalEngine,exec_prefix
from .journal import BufferedJournal
from . import native_loop
from .provider import Provider
from .owned_frames import OwningFrameLifecycle

class FixtureLedger:
    def reserve_request(self,*args):pass
    def settle(self,*args):pass


class NativeAgentFailure(NonZeroAgentExitCodeError):
    """Use Harbor's recoverable agent-failure path so verification still runs.

    This reports the native session outcome, not an invented OS exit code.
    """


def native_outcome(output):
    result=output.get('result')
    present=isinstance(result,dict) and result.get('type')=='result'
    native=result if isinstance(result,dict) else {}
    return dict(success=output.get('terminal')=='completed' and present and native.get('is_error') is False,
                terminal=output.get('terminal'),native_result_present=present,
                native_is_error=native.get('is_error'),native_subtype=native.get('subtype'),
                terminal_reason=native.get('terminal_reason'),api_error_status=native.get('api_error_status'))


def asset_command(config,name):
    mount=config['asset_mount']
    return [part.replace('{assets}',mount) for part in config['commands'][name]]


def command_factory(config,container,user,remote_settings,session_dir,task_env,task_home,task_path,task_cwd):
    def build(folder,model,session,home,options):
        command,env=native_loop.invocation(folder,model,session,home,options)
        command[command.index('--settings')+1]=remote_settings
        command+=['--append-system-prompt',config['system_prompt']]
        # The old loop's host HOME/PATH are never copied into the task.
        env.pop('HOME',None);env.pop('PATH',None)
        env.update(task_env)
        env.update(HOME=task_home,PATH=task_path,CLAUDE_CONFIG_DIR=session_dir)
        env['ANTHROPIC_BASE_URL']=model.url;env['ANTHROPIC_API_KEY']='engineering-dummy-key'
        prefix=exec_prefix(config['docker'],container,user,task_cwd)
        return prefix+['env',*[f'{k}={v}' for k,v in env.items()],*asset_command(config,'claude'),*command[1:]],dict(os.environ)
    return build


class TaskFaithfulClaude(ClaudeCode):
    def __init__(self,*args,faithful_config,**kwargs):
        self.faithful=json.loads(Path(faithful_config).read_text())
        super().__init__(*args,**kwargs)

    async def install(self,environment):
        # No user creation, chmod/chown of the workspace, package install, global
        # symlinks, PATH overrides, security_opt or verifier-mode changes.
        c=self.faithful
        for name,expected in c['asset_sha256'].items():
            if sha(Path(c['assets'])/name)!=expected:raise ValueError('Harness asset changed: '+name)
        for name in ['host_guard','guard_config']:
            if sha(c[name])!=c[name+'_sha256']:raise ValueError('Trusted controller input changed: '+name)
        version=await environment.exec(command=' '.join(shlex.quote(x) for x in asset_command(c,'claude')+['--version']))
        save(self.logs_dir/'native-client-version.json',dict(exit_code=version.return_code,stdout=version.stdout,stderr=version.stderr))
        if version.return_code:raise RuntimeError('Pinned native client cannot run in the original task environment')
        state=c['state_dir']
        result=await environment.exec(command='umask 077; mkdir -p '+shlex.quote(state))
        if result.return_code:raise RuntimeError('Original task user cannot create harness state in /tmp')
        self.remote_settings=state+'/settings.json'
        text=json.dumps({'hasCompletedOnboarding':True})
        result=await environment.exec(command='umask 077; printf %s '+shlex.quote(text)+' > '+shlex.quote(self.remote_settings))
        if result.return_code:raise RuntimeError('Harness settings creation failed')

    async def run(self,instruction,environment,context):
        c=self.faithful;folder=self.logs_dir.parent/'control';folder.mkdir()
        journal=BufferedJournal(folder/'events.jsonl',dict(role='trusted_external_controller',mode=c['mode']))
        docker=c['docker']
        result=await environment._run_docker_compose_command(['ps','-q','main'],check=True)
        container=result.stdout.strip()
        info=json.loads(subprocess.check_output([docker,'inspect',container],text=True))[0]
        validate_container(info,c['image_id'],c['assets'],c['asset_mount'],folder)
        save(folder/'container.json',info)
        # Capture the original Harbor execution context, before any model action.
        identity=await environment.exec(command='id; printf "\\nCAUSHELL_CONTEXT\\000%s\\000%s\\000%s\\000" "$HOME" "$PATH" "$PWD"')
        if identity.return_code:raise RuntimeError('Cannot observe original task context')
        fields=identity.stdout.split('CAUSHELL_CONTEXT\x00')
        if len(fields)!=2:raise ValueError('Task context framing failed')
        home,path,cwd,tail=fields[1].split('\x00')
        if tail or not cwd.startswith('/') or not home.startswith('/'):raise ValueError('Invalid task context')
        task_env=environment._merge_env({})
        image_env=dict(x.split('=',1) for x in info['Config'].get('Env',[]) if '=' in x)
        if any(task_env.get(k,image_env.get(k)) for k in ['LD_PRELOAD','LD_AUDIT']):raise ValueError('This native client asset cannot preserve custom loader instrumentation; do not silently remove it')
        save(folder/'task-context.json',dict(identity=fields[0],home=home,path=path,cwd=cwd,agent_user=c['agent_user'],phase_environment_keys=sorted(task_env),task_config_sha256=c['task_config_sha256']))
        session=str(uuid.uuid4());engine=None;model=None;lifecycle=None
        try:
            engine=ExternalEngine(docker,container,c['agent_user'],asset_command(c,'observer'),c['host_guard'],c['guard_config'],folder,journal,home,cwd)
            lifecycle=OwningFrameLifecycle(session,journal,engine,c['asset_mount']+'/owning-frame.bash',asset_command(c,'observer')) if c.get('owning_frames') else Lifecycle(session,journal,engine)
            if c['mode']=='offline':
                model=MockModel(c['fixture_steps'],FixtureLedger(),session,journal,address=('0.0.0.0',0))
                model.url=f'http://host.docker.internal:{model.server.server_port}'
            elif c['mode']=='local':
                if not c.get('local_model_launch_authorized'):raise ValueError('Local model launch requires explicit run-plan authorization')
                model=Provider(folder/'provider',c['provider'])
            else:raise ValueError('Unsupported mode')
            options=dict(model=c.get('model','fixture-model'),prompt=instruction,output_tokens=c.get('native_max_tokens',32000),cli_budget_usd=None,max_turns=None,max_retries=None,usage_kind='synthetic' if c['mode']=='offline' else 'local',thinking='adaptive',tools='default',environment=dict(CLAUDE_CODE_EFFORT_LEVEL='high'),command_factory=command_factory(c,container,c['agent_user'],self.remote_settings,c['state_dir']+'/sessions',task_env,home,path,cwd))
            worker=asyncio.create_task(asyncio.to_thread(native_loop.run,folder,model,lifecycle,{'hasCompletedOnboarding':True},c['agent_timeout'],Path(home),Path(c['host_workdir']),options=options))
            try:output=await asyncio.shield(worker)
            except asyncio.CancelledError:
                # Publish the cause before waking the native loop so journal
                # consumers and the final result retain the same attribution.
                journal.emit('harbor_cancelled_agent');model.stop_reason='harbor_cancelled';model.stopped.set();output=await worker;output['native_loop_terminal']=output['terminal'];output['terminal']='harbor_cancelled';save(folder/'result.json',output);raise
            save(folder/'result.json',output)
            shutil.copyfile(folder/'claude.stdout.jsonl',self.logs_dir/'claude-code.txt')
            outcome=native_outcome(output)
            save(folder/'native-outcome.json',outcome)
            journal.emit('native_agent_outcome',**outcome)
            if not outcome['success']:
                raise NativeAgentFailure('Native session did not complete: '+json.dumps(outcome,sort_keys=True))
        finally:
            cleanup_errors=[]
            try:
                for name,resource in [('model',model),('frame_gate',lifecycle if hasattr(lifecycle,'close') else None),('guard',engine)]:
                    if resource:
                        try:resource.close()
                        except Exception as error:
                            cleanup_errors.append(name+': '+repr(error))
                capture=folder.parent/'artifacts';capture.mkdir(exist_ok=True)
                for name,source in [('native-session',c['state_dir']),('workspace',cwd)]:
                    if source=='/':continue
                    copied=subprocess.run([docker,'cp',container+':'+source,str(capture/name)],text=True,capture_output=True)
                    save(folder/(name+'-capture.json'),dict(exit_code=copied.returncode,stderr=copied.stderr))
                    if copied.returncode:cleanup_errors.append(name+' capture failed')
                # Preserve upstream services and verifier lifecycle. No blanket root-PID cleanup.
                journal.emit('agent_phase_finished',original_task_config_preserved=True,cleanup_errors=cleanup_errors)
            finally:
                journal.close();save(folder/'journal-overhead.json',journal.overhead())
            if cleanup_errors:raise RuntimeError('; '.join(cleanup_errors))
