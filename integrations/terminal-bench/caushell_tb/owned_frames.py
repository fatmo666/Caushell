"""Pause the real native Bash action, collect facts, then check and approve once."""
from copy import deepcopy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import secrets
import shlex
import threading
import time
from rq3.lifecycle import Lifecycle
from rq3.records import canonical
from .background import BackgroundTasks

_protocol_path=Path(__file__).resolve().parents[2]/'execution-frame/observation.py'
_spec=importlib.util.spec_from_file_location('caushell_owned_frame_protocol',_protocol_path)
protocol=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(protocol)


def wrapped_command(command,gate,endpoint,ticket,nonce,names,observer):
    status='__caushell_status_'+secrets.token_hex(16)
    args=[endpoint,ticket,nonce,status]
    source='builtin source '+shlex.quote(gate)+' '+' '.join(shlex.quote(x) for x in args)+' "$?" '+str(len(observer))+' '+' '.join(shlex.quote(x) for x in [*observer,*names])
    # Source returns after the gate; the user's code is not inside a function or
    # a sourced file. Conditional restoration preserves both $? and errexit.
    return (f'if {source}; then\nif ( builtin exit "${{{status}}}" ); then\n'
            +command+'\nelse\n'+command+'\nfi\nelse\nbuiltin exit 125\nfi')


class FrameServer:
    def __init__(self,lifecycle,gate,observer,address=('0.0.0.0',0),public_host='host.docker.internal'):
        self.lifecycle=lifecycle;self.gate=gate;self.observer=observer
        self.pending={};self.inflight={};self.lock=lifecycle._state_lock;self.closed=False;self.instance_id="rq3-owning-executor-"+secrets.token_hex(16)
        outer=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                try:
                    length=int(self.headers.get('Content-Length','0'))
                    if self.path!='/frame' or not 0<length<=1048576:raise ValueError('Invalid frame envelope')
                    self.connection.settimeout(10)
                    request=json.loads(self.rfile.read(length));response=outer.accept(request)
                    status=200
                except Exception as error:
                    outer.lifecycle.journal.emit('owning_frame_transport_rejected',error=repr(error))
                    response=dict(error='owning-frame request rejected');status=409
                body=json.dumps(response).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        self.server=ThreadingHTTPServer(address,Handler);self.server.daemon_threads=True
        self.endpoint=f'http://{public_host}:{self.server.server_port}/frame'
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()

    def issue(self,tool_id,cwd):
        row=self.lifecycle.actions[tool_id];ticket=secrets.token_hex(32);nonce=secrets.token_hex(16)
        executor=self.instance_id
        plan=self.lifecycle.engine.plan(row['input']['command'],cwd,self.lifecycle.session,executor)
        names=protocol.planned_names(plan)
        command=wrapped_command(row['input']['command'],self.gate,self.endpoint,ticket,nonce,names,self.observer)
        with self.lock:
            if self.closed or len(self.pending)>=256:raise ValueError('Owning executor queue unavailable')
            self.pending[ticket]=dict(tool_id=tool_id,nonce=nonce,names=names,executor=executor,issued_ns=time.monotonic_ns())
            row['executor_input']=dict(row['input'],command=command);row['status']='awaiting_execution_frame';row['frame_status']='pending'
            self.lifecycle.journal.emit('owning_frame_gate_issued',tool_use_id=tool_id,executor=executor,names=list(names),logical_input_sha256=row['input_sha256'],executor_input_sha256=hashlib.sha256(canonical(row['executor_input'])).hexdigest())
        return deepcopy(row['executor_input'])

    def accept(self,request):
        if set(request)!={'ticket','nonce','cwd','raw'}:raise ValueError('Unrecognized observation envelope')
        with self.lock:
            pending=self.pending.get(request['ticket'])
            if not pending or self.closed or request['nonce']!=pending['nonce']:raise ValueError('Unknown, replayed or cross-action observation')
            self.pending.pop(request['ticket'])
            self.inflight[request['ticket']]=pending
        try:
            return self._accept(request,pending)
        finally:
            with self.lock:
                if self.inflight.pop(request['ticket'],None) is not None:
                    row=self.lifecycle.actions[pending['tool_id']]
                    row['frame_status']='failed'
                    if row['status']=='awaiting_execution_frame':row['status']='executor_gate_failed'

    def _active(self,request,pending):
        return not self.closed and self.inflight.get(request['ticket']) is pending

    def _accept(self,request,pending):
        if not isinstance(request['cwd'],str) or not request['cwd'].startswith('/') or '\0' in request['cwd']:raise ValueError('Invalid actual cwd')
        raw=request['raw']
        if not isinstance(raw,list) or len(raw)>protocol.MAX_BYTES or any(type(v) is not int or not 0<=v<=255 for v in raw):raise ValueError('Invalid capture bytes')
        try:
            header,home_kind,home_value,capture=bytes(raw).split(b'\0',3)
            if header!=b'caushell-owning-context-v1' or home_kind not in (b'present',b'absent',b'unknown'):raise ValueError('Invalid owning context')
            home_text=home_value.decode('utf-8',errors='strict')
            if home_kind!=b'present' and home_text:raise ValueError('Invented absent HOME')
            shell_home=home_text if home_kind==b'present' and home_text.startswith('/') else None
        except (ValueError,UnicodeError):
            shell_home=None;capture=b''
        row=self.lifecycle.actions[pending['tool_id']]
        with self.lock:
            if not self._active(request,pending) or row['status']!='awaiting_execution_frame':raise ValueError('Action is not pending')
            row['frame_status']='checking'
        began=time.monotonic_ns();engine=self.lifecycle.engine
        with engine.rpc_lock:
            with self.lock:
                if not self._active(request,pending):return self._answer(request,pending,False,None,began)
            guard=engine.check_observed(row['input']['command'],request['cwd'],self.lifecycle.session,pending['executor'],pending['nonce'],capture,pending['names'],protocol.decode,pending['tool_id'],observed_home=shell_home)
            with self.lock:
                if not self._active(request,pending):
                    self.lifecycle.journal.emit('cancelled_frame_check',tool_use_id=pending['tool_id'],response=guard)
                    return self._answer(request,pending,False,guard['decision'],began)
                row['guard']=guard
                self.lifecycle.journal.emit('guard_decision',tool_use_id=pending['tool_id'],response=guard,source='owning_bash_boundary')
                if guard['decision']=='deny':row['status']='denied'
            decision=guard['decision']
            if decision=='deny':allowed=False
            elif decision=='allow':allowed=True
            elif decision=='need_approval':
                receipt=guard.get('check_receipt')
                if not receipt or receipt['check_id']['session_id']!=self.lifecycle.session:raise ValueError('Guard receipt is missing or cross-session')
                approved=self.lifecycle.approval_policy=='approve'
                response=engine.authorize(receipt,approved=approved,tool_use_id=pending['tool_id'])
                if response.get('approved')!=approved or response['check_id']!=receipt['check_id']:raise ValueError('Guard authorization was not accepted')
                with self.lock:
                    self.lifecycle.confirmations+=1
                    row['approval']=dict(source='simulated_user',confirmation=self.lifecycle.confirmations,guard_trigger=True,native_callback=False,executor_callback=True,receipt=receipt,approved=approved)
                    self.lifecycle.journal.emit('single_call_approval',tool_use_id=pending['tool_id'],approval=row['approval'],input_sha256=row['input_sha256'])
                allowed=approved
            else:raise ValueError('Unknown guard decision')
            with self.lock:
                if not self._active(request,pending):return self._answer(request,pending,False,decision,began)
                # Linearization point: cancellation before this commit cannot
                # release the body, even if the check/authorization RPC was in flight.
                self.inflight.pop(request['ticket'])
                row['frame_status']='authorized' if allowed else 'blocked'
                row['status']=('approved' if decision=='need_approval' else 'proposed') if allowed else ('denied' if decision=='deny' else 'rejected')
                self.lifecycle.background.apply(row)
                return self._answer(request,pending,allowed,decision,began)

    def _answer(self,request,pending,allowed,decision,began):
        self.lifecycle.journal.emit('owning_frame_gate_finished',tool_use_id=pending['tool_id'],allowed=allowed,decision=decision,elapsed_ns=time.monotonic_ns()-began)
        return dict(protocol=1,ticket=request['ticket'],allowed=allowed,decision=decision,reason='Caushell authorized the single action' if allowed else 'Action not released: denied, declined, or cancelled')

    def cancel(self,tool_id):
        with self.lock:
            self.pending={k:v for k,v in self.pending.items() if v['tool_id']!=tool_id}
            self.inflight={k:v for k,v in getattr(self,'inflight',{}).items() if v['tool_id']!=tool_id}
            if hasattr(self,'lifecycle'):
                row=self.lifecycle.actions.get(tool_id)
                if row and row.get('frame_status') in ('pending','checking'):row['frame_status']='cancelled'

    def cancel_all(self):
        with self.lock:
            self.closed=True
            for row in self.lifecycle.actions.values():self.cancel(row['tool_use_id'])

    def close(self):
        self.cancel_all()
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=5)


class OwningFrameLifecycle(Lifecycle):
    def __init__(self,session,journal,engine,gate,observer,approval_policy='approve',**server_options):
        super().__init__(session,journal,engine,approval_policy)
        if engine.identity.get('frame_submit_protocol')!=1:raise ValueError('Observer lacks owning-frame transport support')
        self._state_lock=threading.RLock();self._finished=False
        self.background=BackgroundTasks(self)
        self.frames=FrameServer(self,gate,observer,**server_options)

    def before(self,tool_id,payload):
        with self._state_lock:
            if self._finished:raise ValueError('Action after session finish')
            if payload['tool_name']!='Bash':return super().before(tool_id,payload)
            if payload['session_id']!=self.session or not tool_id or tool_id in self.actions:raise ValueError('Duplicate or cross-session action')
            original=deepcopy(payload['tool_input'])
            row=dict(tool_use_id=tool_id,session_id=self.session,tool='Bash',input=original,input_sha256=hashlib.sha256(canonical(original)).hexdigest(),status='proposed',guard=None,approval=None,tool_result=None)
            self.actions[tool_id]=row;self.journal.emit('proposal',action=deepcopy(row))
        updated=self.frames.issue(tool_id,payload['cwd'])
        # This enters only the trusted gate. No Caushell Allow or approval is
        # fabricated before the actual execution frame exists.
        return dict(hookSpecificOutput=dict(hookEventName='PreToolUse',updatedInput=updated))

    def approve(self,tool_id,tool,original):
        with self._state_lock:
            if self._finished:raise ValueError('Gate admission after session finish')
            row=self.actions.get(tool_id)
            if row and row['tool']=='Bash':
                if row['status']!='awaiting_execution_frame':raise ValueError('Gate admission is no longer pending')
                if tool!='Bash' or original not in (row['input'],row['executor_input']):raise ValueError('Native gate input mismatch')
                self.journal.emit('native_executor_gate_admitted',tool_use_id=tool_id,guard_checked=False)
                return dict(behavior='allow',updatedInput=deepcopy(row['executor_input']))
        return super().approve(tool_id,tool,original)

    def after(self,tool_id,payload,failed=False):
        with self._state_lock:return self._after(tool_id,payload,failed)

    def _after(self,tool_id,payload,failed):
        row=self.actions.get(tool_id)
        if row and row['tool']=='Bash':
            if payload['session_id']!=self.session or payload['tool_name']!='Bash' or payload['tool_input'] not in (row['input'],row['executor_input']):raise ValueError('Native executor result mismatch')
            response=payload.get('tool_response',{})
            background=(response.get('backgroundTaskId') or response.get('background_task_id')) if isinstance(response,dict) else None
            if background and not failed:
                self.background.register(row,background,True)
                logical=deepcopy(payload);logical['tool_input']=deepcopy(row['input'])
                row['tool_result']=logical
                self.journal.emit('background_task_registered',tool_use_id=tool_id,result=logical)
                self.background.apply(row)
                return
            self.frames.cancel(tool_id)
            if row['status'] in ('denied','rejected','awaiting_execution_frame'):
                if not failed:raise ValueError('An unapproved action claims execution')
                if row['status']=='awaiting_execution_frame':row['status']='executor_gate_failed'
                row['tool_result']=deepcopy(payload);self.journal.emit('executor_block_reported',tool_use_id=tool_id,status=row['status'],result=payload);return
            payload=deepcopy(payload);payload['tool_input']=deepcopy(row['input'])
            if row.get('native_task',{}).get('backgrounded'):
                if row.get('frame_status')!='authorized':raise ValueError('An unapproved action claims execution')
                terminal='failed' if failed else 'completed'
                old=row['native_task']['state']
                if old in ('completed','failed','stopped') and old!=terminal:raise ValueError('Native task terminal state changed')
                row['native_task'].update(state=terminal,terminal_source='native_post_tool_use')
                row['tool_result']=payload
                self.background.apply(row)
                return
        return super().after(tool_id,payload,failed)

    def observe_native(self,message):
        with self._state_lock:
            if self._finished:return False
            return self.background.observe(message)

    def pending_background(self):
        with self._state_lock:return self.background.pending()

    def native_denials(self,result):
        with self._state_lock:return self._native_denials(result)

    def _native_denials(self,result):
        result=deepcopy(result)
        for denial in result.get('permission_denials',[]):
            row=self.actions.get(denial['tool_use_id'])
            if row and row['tool']=='Bash' and denial['tool_input']==row.get('executor_input'):
                self.frames.cancel(row['tool_use_id']);denial['tool_input']=deepcopy(row['input'])
        return super().native_denials(result)

    def finish(self):
        with self._state_lock:
            self._finished=True;self.frames.cancel_all()
            for row in self.actions.values():
                if row['status']=='awaiting_execution_frame':
                    row['status']='unresolved'
                    self.journal.emit('execution_unresolved',tool_use_id=row['tool_use_id'])
            return deepcopy(super().finish())

    def close(self):self.frames.close()
