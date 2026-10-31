"""Correlate native task events; task allocation never grants execution rights."""
from copy import deepcopy


class BackgroundTasks:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle
        self.owners = {}

    def register(self, row, task_id, backgrounded=None):
        if not isinstance(task_id, str) or not task_id or '\0' in task_id:
            raise ValueError('Invalid native task ID')
        tool_id = row['tool_use_id']
        if task_id in self.owners and self.owners[task_id] != tool_id:
            raise ValueError('Native task belongs to another action')
        task = row.get('native_task')
        if task and task['task_id'] != task_id:
            raise ValueError('Native task ID changed for an action')
        if task is None:
            task = row['native_task'] = dict(task_id=task_id, backgrounded=False, state='running')
        self.owners[task_id] = tool_id
        # A task can be moved to the background automatically after submission.
        task['backgrounded'] |= backgrounded is True or row['input'].get('run_in_background') is True
        return task

    def apply(self, row):
        task = row.get('native_task')
        if not task or not task['backgrounded']:
            return
        status = task['state']
        if row.get('frame_status') != 'authorized':
            if status == 'completed':
                raise ValueError('An unapproved action claims background completion')
            if status in ('failed', 'stopped'):
                self.lifecycle.frames.cancel(row['tool_use_id'])
                if row['status'] not in ('denied', 'rejected', 'native_denied', 'executor_gate_failed', 'unresolved'):
                    row['status'] = 'executor_gate_failed'
                    self.lifecycle.journal.emit('executor_block_reported', tool_use_id=row['tool_use_id'],
                                                status=row['status'], native_task=deepcopy(task))
            return
        target = {'completed': 'executed', 'failed': 'execution_failed',
                  'stopped': 'execution_failed'}.get(status, 'background_unresolved')
        if row['status'] != target:
            row['status'] = target
            self.lifecycle.journal.emit(target, tool_use_id=row['tool_use_id'],
                                        source='native_background_task', native_task=deepcopy(task))

    def observe(self, message):
        if message.get('type') != 'system' or message.get('subtype') not in (
                'task_started', 'task_updated', 'task_notification'):
            return False
        task_id = message.get('task_id')
        owner = self.owners.get(task_id)
        supplied = message.get('tool_use_id')
        row = self.lifecycle.actions.get(owner or supplied)
        if row is None or row['tool'] != 'Bash':
            return False
        if message.get('session_id') != self.lifecycle.session or (owner and supplied and owner != supplied):
            raise ValueError('Cross-session or cross-action native task event')
        kind = message['subtype']
        if kind == 'task_started' and message.get('task_type') not in (None, 'local_bash'):
            raise ValueError('Native Bash task type mismatch')
        task = self.register(row, task_id, message.get('is_backgrounded'))
        if kind == 'task_updated':
            patch = message.get('patch')
            if not isinstance(patch, dict):
                raise ValueError('Invalid native task patch')
            task['backgrounded'] |= patch.get('is_backgrounded') is True
            status = patch.get('status')
        else:
            status = message.get('status')
        if status is not None:
            normalized = {'killed': 'stopped'}.get(status, status)
            if normalized not in ('pending', 'running', 'paused', 'completed', 'failed', 'stopped'):
                raise ValueError('Unknown native task state')
            if task['state'] in ('completed', 'failed', 'stopped') and normalized != task['state']:
                if normalized in ('pending', 'running', 'paused'):
                    self.lifecycle.journal.emit('native_task_stale_update', tool_use_id=row['tool_use_id'], message=message)
                    return True
                raise ValueError('Native task terminal state changed')
            task['state'] = normalized
            if normalized in ('completed', 'failed', 'stopped'):
                task['terminal_source'] = kind
                if 'usage' in message:task['reported_usage'] = deepcopy(message['usage'])
        self.lifecycle.journal.emit('native_task_observed', tool_use_id=row['tool_use_id'], message=message)
        self.apply(row)
        return True

    def pending(self):
        return any(row.get('native_task', {}).get('backgrounded')
                   and row['native_task']['state'] not in ('completed', 'failed', 'stopped')
                   and row['status'] not in ('executor_gate_failed', 'unresolved', 'native_denied')
                   for row in self.lifecycle.actions.values())
