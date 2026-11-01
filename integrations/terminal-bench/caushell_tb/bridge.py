"""External guard/store and a private, non-dumpable target-namespace observer."""
import json
import os
from pathlib import Path
from .native_inventory import LOADER_NAMES, verified_variants
import select
import socket
import subprocess
import threading
import time

MAX_PACKET=2*1024*1024
ALLOWED={'entry','file','directory','runtime_file','account'}


def line(stream, timeout=10):
    # read1/readline can wait forever after a partial packet. Apply one deadline
    # to the whole frame, not merely to its first byte.
    deadline=time.monotonic()+timeout;raw=b''
    while b'\n' not in raw:
        remaining=deadline-time.monotonic()
        if remaining<=0 or not select.select([stream],[],[],remaining)[0]:raise TimeoutError('Private observation channel timed out')
        part=os.read(stream.fileno(),min(65536,MAX_PACKET+1-len(raw)))
        if not part:raise ValueError('Observation packet is incomplete or over budget')
        raw+=part
        if len(raw)>MAX_PACKET:raise ValueError('Observation packet is incomplete or over budget')
    packet,extra=raw.split(b'\n',1)
    if extra:raise ValueError('Unsolicited observation data')
    return json.loads(packet)


def exec_prefix(docker, container, user=None, cwd=None):
    if len(container)!=64 or any(c not in '0123456789abcdef' for c in container):raise ValueError('Full immutable container ID required')
    command=[docker,'exec','-i']
    if user is not None:command+=['--user',str(user)]
    if cwd is not None:command+=['--workdir',cwd]
    return command+[container]


class ExternalEngine:
    def __init__(self,docker,container,user,observer_command,host_binary,config,folder,journal,home,workspace,native_inventory=None):
        self.native_inventory=native_inventory or {}
        self.observer_lock=threading.Lock()
        self.native_observation_id=0
        self.journal,self.home,self.workspace=journal,home,workspace
        self.buffer=b'';self.failed=None;self.closed=False;self.rpc_lock=threading.RLock()
        folder=Path(folder);folder.mkdir(exist_ok=True)
        self.observer_stderr=(folder/'observer.stderr.log').open('xb')
        self.stderr=(folder/'caushell.stderr.log').open('xb')
        # The observation process alone has dumpability/NNP restrictions. The task does not.
        self.observer=None;self.process=None;self.parent=None;self.thread=None;self.observer_reader=None
        try:
            self.observer=subprocess.Popen(exec_prefix(docker,container,user)+['env','-u','LD_PRELOAD','-u','LD_AUDIT',*observer_command,'observe'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.observer_stderr,bufsize=0)
            import io
            self.observer_reader=io.BufferedReader(self.observer.stdout)
            self.identity=line(self.observer_reader)
            if self.identity.get('observer_protocol')!=1 or self.identity.get('protected') is not True:
                raise ValueError('Target observer lacks process protection')
            self.journal.emit('observer_ready',identity=self.identity)
            parent,child=socket.socketpair();self.parent=parent
            try:
                self.process=subprocess.Popen([str(host_binary),'serve',str(child.fileno()),str(config),str(folder/'guard-store')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.stderr,pass_fds=[child.fileno()])
            finally:child.close()
            self.thread=threading.Thread(target=self._observations,daemon=True);self.thread.start()
            if self.call(dict(kind='ping'))['approval_protocol']!=1:raise ValueError('Guard approval protocol unavailable')
        except BaseException:
            self.close(raise_errors=False)
            raise

    def _observations(self):
        reader=self.parent.makefile('rb');writer=self.parent.makefile('wb')
        try:
            while True:
                raw=reader.readline(MAX_PACKET+1)
                if not raw:return
                if len(raw)>MAX_PACKET or not raw.endswith(b'\n'):raise ValueError('Invalid guard observation frame')
                request=json.loads(raw)
                if set(request)!={'id','op','path','limit'} or request['op'] not in ALLOWED or not isinstance(request['id'],int):raise ValueError('Unrecognized observation request')
                response=self._observe(request)
                writer.write(json.dumps(response).encode()+b'\n');writer.flush()
        except BaseException as error:
            self.failed=repr(error)
            self.journal.emit('namespace_observation_failure',error=self.failed)
            try:self.parent.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        finally:reader.close();writer.close()

    def _observe(self,request):
        with self.observer_lock:
            if self.observer.poll() is not None:raise EOFError('Namespace observer exited')
            began=time.monotonic_ns()
            self.observer.stdin.write(json.dumps(request).encode()+b'\n');self.observer.stdin.flush()
            response=line(self.observer_reader)
            if response.get('request')!=request:raise ValueError('Cross-request observation response')
            self.journal.emit('namespace_observation',request=request,response=response,elapsed_ns=time.monotonic_ns()-began)
            return response

    def _native_file(self,path):
        self.native_observation_id+=1
        response=self._observe(dict(id=(1<<63)+self.native_observation_id,op='runtime_file',path=path,limit=None))
        return response.get('value',{})

    def call(self, request, tool_use_id=None):
        with self.rpc_lock:return self._call(request,tool_use_id)

    def _call(self, request, tool_use_id=None):
        if self.failed:raise RuntimeError(self.failed)
        began=time.monotonic_ns();self.journal.emit('caushell_request',request=request,tool_use_id=tool_use_id)
        self.process.stdin.write(json.dumps(request).encode()+b'\n');self.process.stdin.flush()
        while b'\n' not in self.buffer:
            if not select.select([self.process.stdout],[],[],20)[0]:raise TimeoutError('Guard response timed out')
            data=self.process.stdout.read1(65536)
            if not data:raise EOFError('Guard exited')
            self.buffer+=data
            if len(self.buffer)>32*1024*1024:raise ValueError('Guard frame exceeds budget')
        raw,self.buffer=self.buffer.split(b'\n',1);response=json.loads(raw)
        if self.failed:raise RuntimeError(self.failed)
        if response.get('kind')!=request['kind']:raise ValueError('Guard response mismatch')
        self.journal.emit('caushell_response',response=response,tool_use_id=tool_use_id,wire_elapsed_ns=time.monotonic_ns()-began)
        return response['payload']

    def request(self,command,cwd,session,intent='propose_for_execution'):
        return dict(intent=intent,session_id=session,command=command,shell_kind='bash',home=self.home,workspace_root=self.workspace,shell_state_before=dict(cwd=cwd,observability=dict(variables='unknown',aliases='unknown',functions='unknown')),runtime=dict(runtime_name='rq3_claude_code',tool_name='Bash',shell_runtime_capabilities=dict(persists_cwd=True,persists_variables=False,persists_exported_environment=False,persists_aliases=False,persists_functions=False,persists_positionals=False)))

    def plan(self,command,cwd,session,executor,home=None,home_is_actual=False):
        request=self.request(command,cwd,session)
        if home_is_actual:request['home']=home
        plan=self.call(dict(kind='execution_frame_plan',payload=dict(request=request,executor_instance_id=executor)))
        inventory=getattr(self,'native_inventory',{})
        if inventory.get('commands'):
            names=sorted(set(plan['requirements']['environment_names'])|set(LOADER_NAMES))
            if len(names)<=128:
                plan['requirements']['environment_names']=names
                plan['requirements']['native_command_names']=sorted(inventory['commands'])
        return plan

    def check(self,command,cwd,session,intent='propose_for_execution',tool_use_id=None):
        # Legacy hooks still preserve unknown facts; they never probe another Shell.
        return self.call(dict(kind='check',payload=self.request(command,cwd,session,intent)),tool_use_id)

    def check_observed(self,command,cwd,session,executor,nonce,raw,names,decode,tool_use_id,observed_home=None,native_variants=None):
        with self.rpc_lock:
            plan=self.plan(command,cwd,session,executor,home=observed_home,home_is_actual=True)
            if tuple(plan['requirements']['environment_names'])!=tuple(names):raise ValueError('Execution-frame requirements changed while paused')
            request=self.request(command,cwd,session);request['home']=observed_home
            try:
                frame=decode(plan,nonce,raw)
                lookups=frame.pop('_native_executables',{})
                inventory=getattr(self,'native_inventory',{})
                if inventory.get('commands'):
                    verified=verified_variants(inventory,frame,lookups,self._native_file)
                    self.journal.emit('native_implementation_evidence',tool_use_id=tool_use_id,verified=verified,requested=sorted(inventory['commands']))
                    if verified:frame['native_variants']=verified
                if native_variants:frame['native_variants']=dict(native_variants)
                request['shell_state_before']['execution_frame']=frame
            except ValueError as error:
                # Discard invalid facts. Still analyze the registered original
                # command so independent Deny and missing-fact Ask remain visible.
                self.journal.emit('execution_frame_unavailable',tool_use_id=tool_use_id,error=repr(error))
            return self.call(dict(kind='check',payload=request),tool_use_id)

    def authorize(self,receipt,approved=True,tool_use_id=None):
        return self.call(dict(kind='authorize',payload=dict(**receipt,approved=approved,authority='simulated_user')),tool_use_id)

    def close(self,raise_errors=True):
        if self.closed:return
        self.closed=True
        errors=[]
        for process in [self.process,self.observer]:
            if not process:continue
            try:
                if process.stdin and not process.stdin.closed:process.stdin.close()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                errors.append('transport forced to stop')
            if process.returncode:errors.append('transport exit '+str(process.returncode))
        if self.parent:
            try:self.parent.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        if self.thread:self.thread.join(timeout=5)
        if self.parent:self.parent.close()
        for stream in [self.observer_reader,self.process.stdout if self.process else None,self.stderr,self.observer_stderr]:
            if stream:stream.close()
        if self.failed:errors.append(self.failed)
        self.journal.emit('observation_transport_closed',errors=errors)
        if errors and raise_errors:raise RuntimeError('; '.join(errors))
