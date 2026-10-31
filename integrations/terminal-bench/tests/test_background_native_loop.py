"""Native stdio protocol fixtures; never connect to a model endpoint."""
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from caushell_tb import native_loop
from caushell_tb.journal import BufferedJournal


class Model:
    url = 'http://unused.invalid'

    def __init__(self):
        self.stopped = threading.Event()


class Lifecycle:
    session = 's'
    confirmations = 0

    def __init__(self, journal):
        self.journal = journal
        self.actions = {}

    def observe_native(self, message):
        if message.get('subtype') == 'task_started':
            self.actions['a'] = dict(status='background_unresolved')
        elif message.get('subtype') in ('task_notification', 'task_updated'):
            status = message.get('status') or message.get('patch', {}).get('status')
            if status in ('completed', 'failed', 'stopped', 'killed'):
                self.actions['a']['status'] = 'executed' if status == 'completed' else 'execution_failed'

    def pending_background(self):
        return any(row['status'] == 'background_unresolved' for row in self.actions.values())

    def native_denials(self, message):
        pass

    def cancel_pending(self):
        self.journal.emit('fixture_pending_gates_cancelled')

    def finish(self):
        return deepcopy(list(self.actions.values()))


def task(subtype, **kwargs):
    return dict(type='system', subtype=subtype, task_id='bg-a', tool_use_id='a', session_id='s', **kwargs)


def result(ident, is_error=False):
    return dict(type='result', uuid=ident, session_id='s', is_error=is_error, permission_denials=[])


class NativeBackgroundTests(unittest.TestCase):
    def trial(self, messages, timeout=3, model=None):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            fixture = folder / 'native-protocol-fixture.py'
            fixture.write_text('''import json,sys
request=json.loads(sys.stdin.readline())
print(json.dumps(dict(type='control_response',response=dict(request_id=request['request_id'],subtype='success'))),flush=True)
json.loads(sys.stdin.readline())
for row in json.loads(sys.argv[1]):print(json.dumps(row),flush=True)
for line in sys.stdin:pass
''')
            def command_factory(*args):
                return [sys.executable, '-B', str(fixture), json.dumps(messages)], dict(os.environ)
            journal = BufferedJournal(folder / 'events.jsonl')
            life = Lifecycle(journal)
            try:
                value = native_loop.run(folder, model or Model(), life, {}, timeout, folder, folder,
                                        options=dict(command_factory=command_factory))
            finally:
                journal.close()
            return value, [json.loads(line) for line in (folder / 'events.jsonl').read_text().splitlines()]

    def test_turn_result_waits_for_background_notification_and_followup_result(self):
        value, rows = self.trial([task('task_started'), result('first'),
                                  task('task_notification', status='completed'), result('final')])
        self.assertEqual(value['terminal'], 'completed')
        self.assertEqual(value['result']['uuid'], 'final')
        self.assertEqual(value['actions'][0]['status'], 'executed')
        self.assertEqual(sum(r['kind'] == 'native_result_deferred' for r in rows), 1)

    def test_patch_only_completion_is_consumed_before_the_final_result(self):
        value, _ = self.trial([task('task_started'), result('first'),
                               task('task_updated', patch=dict(status='completed')), result('final')])
        self.assertEqual(value['result']['uuid'], 'final')
        self.assertEqual(value['actions'][0]['status'], 'executed')

    def test_failed_background_command_does_not_terminate_the_followup_turn(self):
        value, _ = self.trial([task('task_started'), result('first'),
                               task('task_notification', status='failed'), result('recovered')])
        self.assertEqual(value['result']['uuid'], 'recovered')
        self.assertEqual(value['actions'][0]['status'], 'execution_failed')

    def test_missing_completion_obeys_the_original_timeout_and_keeps_unresolved_evidence(self):
        value, rows = self.trial([task('task_started'), result('first')], timeout=.2)
        self.assertEqual(value['terminal'], 'timeout')
        self.assertEqual(value['actions'][0]['status'], 'background_unresolved')
        kinds = [r['kind'] for r in rows]
        self.assertLess(kinds.index('fixture_pending_gates_cancelled'), kinds.index('agent_process_exit'))

    def test_native_agent_error_can_end_the_session_with_background_work_unresolved(self):
        value, _ = self.trial([task('task_started'), result('error', is_error=True)])
        self.assertEqual(value['terminal'], 'agent_error')
        self.assertEqual(value['actions'][0]['status'], 'background_unresolved')

    def test_foreground_result_still_finishes_without_waiting_for_extra_messages(self):
        value, rows = self.trial([result('foreground')])
        self.assertEqual(value['terminal'], 'completed')
        self.assertFalse(any(r['kind'] == 'native_result_deferred' for r in rows))

    def test_stop_event_preserves_explicit_cause_and_does_not_invent_a_budget(self):
        for reason in [None, 'harbor_cancelled', 'provider_closed', 'budget_exhausted']:
            with self.subTest(reason=reason):
                model = Model()
                model.stop_reason = reason
                model.stopped.set()
                value, rows = self.trial([], timeout=30, model=model)
                expected = reason or 'stop_requested'
                self.assertEqual(value['terminal'], expected)
                self.assertLess(value['elapsed_seconds'], 5)
                self.assertEqual([r['data']['terminal'] for r in rows
                                  if r['kind'] == 'agent_loop_stopped'], [expected])


if __name__ == '__main__':
    unittest.main()
