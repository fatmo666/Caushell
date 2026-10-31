"""Deterministic callback/frame ordering, without a model or task container."""
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from caushell_tb.owned_frames import OwningFrameLifecycle


class Journal:
    def __init__(self):
        self.rows = []

    def emit(self, kind, **data):
        self.rows.append((kind, deepcopy(data)))


class Engine:
    identity = {'frame_submit_protocol': 1}

    def __init__(self, decision='allow', block=None):
        self.rpc_lock = threading.RLock()
        self.decision = decision
        self.checked = []
        self.approvals = []
        self.block = block
        self.entered = threading.Event()

    def plan(self, command, cwd, session, executor):
        return dict(binding=dict(executor_instance_id=executor),
                    requirements=dict(environment_names=[], pathname=True))

    def check_observed(self, *args, **kwargs):
        self.checked.append(args[0])
        self.entered.set()
        if self.block is not None and not self.block.wait(3):
            raise TimeoutError('Test did not release the fake check')
        return dict(decision=self.decision, reasons=[],
                    check_receipt=dict(check_id=dict(session_id='s', sequence_no=1), state_revision=1))

    def authorize(self, receipt, approved, tool_use_id):
        self.approvals.append((tool_use_id, approved, receipt))
        return dict(approved=approved, check_id=receipt['check_id'])


@contextmanager
def lifecycle(decision='allow', policy='approve', block=None):
    # The HTTP transport is exercised by test_owned_frames; these tests control
    # exact callback order and use the real ticket/check/lifecycle implementation.
    with patch('caushell_tb.owned_frames.ThreadingHTTPServer') as server:
        server.return_value.server_port = 1234
        life = OwningFrameLifecycle('s', Journal(), Engine(decision, block), '/gate', ['/observer'],
                                    approval_policy=policy)
        try:
            yield life
        finally:
            life.close()


def prepare(life, ident='a', background=True):
    original = dict(session_id='s', tool_name='Bash', cwd='/app',
                    tool_input=dict(command='printf payload', run_in_background=background))
    wrapped = life.before(ident, original)['hookSpecificOutput']['updatedInput']
    life.approve(ident, 'Bash', wrapped)
    ticket, item = next((t, r) for t, r in life.frames.pending.items() if r['tool_id'] == ident)
    request = dict(ticket=ticket, nonce=item['nonce'], cwd='/app', raw=[])
    post = dict(original, tool_input=wrapped, tool_response={'backgroundTaskId': 'bg-' + ident})
    return request, post


def notice(life, ident='a', task_id=None, status='completed', subtype='task_notification'):
    message = dict(type='system', subtype=subtype, session_id='s', task_id=task_id or 'bg-' + ident,
                   tool_use_id=ident, status=status, output_file='', summary='fixture')
    life.observe_native(message)


class BackgroundFrameTests(unittest.TestCase):
    def test_background_callback_before_frame_keeps_one_use_ticket_and_no_authority(self):
        with lifecycle('need_approval') as life:
            request, post = prepare(life)
            life.after('a', post)
            self.assertIn(request['ticket'], life.frames.pending)
            self.assertIsNone(life.actions['a']['guard'])
            self.assertFalse(life.engine.approvals)
            self.assertFalse(life.engine.checked)
            result = life.frames.accept(request)
            self.assertTrue(result['allowed'])
            self.assertEqual(life.engine.approvals[0][:2], ('a', True))
            self.assertEqual(life.actions['a']['status'], 'background_unresolved')
            with self.assertRaises(ValueError):
                life.frames.accept(request)

    def test_callback_during_frame_check_does_not_cancel_or_wait_on_the_check(self):
        release = threading.Event()
        with lifecycle('need_approval', block=release) as life:
            request, post = prepare(life)
            answers = []
            errors = []
            def accept():
                try:
                    answers.append(life.frames.accept(request))
                except Exception as error:
                    errors.append(error)
            worker = threading.Thread(target=accept)
            worker.start()
            try:
                self.assertTrue(life.engine.entered.wait(1))
                life.after('a', post)
                self.assertFalse(life.engine.approvals)
                self.assertEqual(life.actions['a']['status'], 'awaiting_execution_frame')
            finally:
                release.set()
                worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])
            self.assertTrue(answers[0]['allowed'])

    def test_late_frame_after_failure_cannot_release_or_authorize_the_body(self):
        release = threading.Event()
        with lifecycle('need_approval', block=release) as life:
            request, post = prepare(life)
            answers = []
            worker = threading.Thread(target=lambda: answers.append(life.frames.accept(request)))
            worker.start()
            try:
                self.assertTrue(life.engine.entered.wait(1))
                life.after('a', dict(post, tool_response={}, error='executor cancelled'), failed=True)
            finally:
                release.set()
                worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertFalse(answers[0]['allowed'])
            self.assertFalse(life.engine.approvals)
            self.assertEqual(life.actions['a']['status'], 'executor_gate_failed')

    def test_deny_and_declined_approval_remain_blocked_after_background_allocation(self):
        for decision, policy, expected in [('deny', 'approve', 'denied'),
                                           ('need_approval', 'reject', 'rejected')]:
            with self.subTest(decision=decision), lifecycle(decision, policy) as life:
                request, post = prepare(life)
                life.after('a', post)
                self.assertFalse(life.frames.accept(request)['allowed'])
                notice(life, status='failed')
                self.assertEqual(life.actions['a']['status'], expected)
                self.assertFalse(life.pending_background())

    def test_frame_before_callback_and_terminal_notifications_finish_exactly_once(self):
        with lifecycle() as life:
            request, post = prepare(life)
            self.assertTrue(life.frames.accept(request)['allowed'])
            life.after('a', post)
            self.assertTrue(life.pending_background())
            notice(life)
            notice(life)
            self.assertEqual(life.actions['a']['status'], 'executed')
            self.assertFalse(life.pending_background())
            self.assertEqual(sum(k == 'executed' for k, _ in life.journal.rows), 1)

    def test_task_updated_alone_can_finish_the_mapped_background_task(self):
        with lifecycle() as life:
            request, post = prepare(life)
            life.after('a', post)
            life.frames.accept(request)
            life.observe_native(dict(type='system', subtype='task_updated', session_id='s',
                                     task_id='bg-a', patch=dict(status='completed')))
            self.assertEqual(life.actions['a']['status'], 'executed')

    def test_completion_before_the_allocation_callback_keeps_the_terminal_state(self):
        with lifecycle() as life:
            request, post = prepare(life)
            life.observe_native(dict(type='system', subtype='task_started', session_id='s', task_id='bg-a',
                                     tool_use_id='a', task_type='local_bash', is_backgrounded=True))
            self.assertIsNone(life.actions['a']['guard'])
            self.assertEqual(life.actions['a']['status'], 'awaiting_execution_frame')
            life.frames.accept(request)
            notice(life)
            life.after('a', post)
            life.observe_native(dict(type='system', subtype='task_updated', session_id='s', task_id='bg-a',
                                     patch=dict(status='running')))
            self.assertEqual(life.actions['a']['status'], 'executed')
            self.assertFalse(life.pending_background())

    def test_task_automatically_backgrounded_can_return_a_final_foreground_result(self):
        with lifecycle() as life:
            request, post = prepare(life, background=False)
            life.observe_native(dict(type='system', subtype='task_started', session_id='s', task_id='bg-a',
                                     tool_use_id='a', task_type='local_bash', is_backgrounded=True))
            life.frames.accept(request)
            life.after('a', dict(post, tool_response={'stdout': 'finished before allocation returned'}))
            self.assertEqual(life.actions['a']['status'], 'executed')
            self.assertFalse(life.pending_background())

    def test_session_finish_during_check_does_not_mutate_the_final_snapshot_or_approve(self):
        release = threading.Event()
        with lifecycle('need_approval', block=release) as life:
            request, _ = prepare(life)
            answers = []
            worker = threading.Thread(target=lambda: answers.append(life.frames.accept(request)))
            worker.start()
            try:
                self.assertTrue(life.engine.entered.wait(1))
                snapshot = life.finish()
            finally:
                release.set()
                worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertFalse(answers[0]['allowed'])
            self.assertIsNone(snapshot[0]['guard'])
            self.assertEqual(snapshot[0]['status'], 'unresolved')
            self.assertFalse(life.engine.approvals)
            self.assertIn('cancelled_frame_check', [k for k, _ in life.journal.rows])

    def test_cancellation_while_authorization_is_in_flight_cannot_release_the_body(self):
        entered, release = threading.Event(), threading.Event()
        with lifecycle('need_approval') as life:
            request, post = prepare(life)
            original = life.engine.authorize
            def authorize(*args, **kwargs):
                entered.set()
                if not release.wait(3):raise TimeoutError('Test authorization not released')
                return original(*args, **kwargs)
            life.engine.authorize = authorize
            answers = []
            worker = threading.Thread(target=lambda: answers.append(life.frames.accept(request)))
            worker.start()
            try:
                self.assertTrue(entered.wait(1))
                life.after('a', dict(post, tool_response={}, error='cancelled'), failed=True)
            finally:
                release.set()
                worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertFalse(answers[0]['allowed'])
            self.assertEqual(life.actions['a']['status'], 'executor_gate_failed')
            self.assertTrue(life.actions['a']['approval']['approved'])  # Retain the unused receipt honestly.

    def test_native_stop_before_frame_cancels_ticket_without_an_approval(self):
        with lifecycle('need_approval') as life:
            request, post = prepare(life)
            life.after('a', post)
            notice(life, status='stopped')
            with self.assertRaises(ValueError):life.frames.accept(request)
            self.assertFalse(life.engine.checked)
            self.assertFalse(life.engine.approvals)

    def test_failure_callback_after_native_stop_keeps_the_gate_blocked(self):
        with lifecycle('need_approval') as life:
            request, post = prepare(life)
            life.after('a', post)
            notice(life, status='stopped')
            life.after('a', dict(post, tool_response={}, error='cancelled'), failed=True)
            self.assertEqual(life.actions['a']['status'], 'executor_gate_failed')
            with self.assertRaises(ValueError):life.frames.accept(request)
            self.assertFalse(life.engine.approvals)

    def test_cancelled_authorized_background_task_accepts_late_failure_without_success(self):
        with lifecycle() as life:
            request, post = prepare(life)
            life.after('a', post)
            life.frames.accept(request)
            notice(life, status='stopped')
            life.after('a', dict(post, tool_response={}, error='stopped'), failed=True)
            notice(life, status='failed')
            self.assertEqual(life.actions['a']['status'], 'execution_failed')
            self.assertEqual(life.actions['a']['native_task']['state'], 'stopped')

    def test_wrong_tool_callback_and_unmapped_task_event_do_not_consume_a_ticket(self):
        with lifecycle() as life:
            request, post = prepare(life)
            with self.assertRaises(ValueError):life.after('a', dict(post, tool_name='Read'))
            self.assertFalse(life.observe_native(dict(type='system', subtype='task_updated', session_id='s',
                                                      task_id='unknown', patch=dict(status='completed'))))
            self.assertIn(request['ticket'], life.frames.pending)

    def test_missing_or_cross_session_receipt_never_releases_the_frame(self):
        for receipt in [None, dict(check_id=dict(session_id='other', sequence_no=1))]:
            with self.subTest(receipt=receipt), lifecycle('need_approval') as life:
                request, post = prepare(life)
                life.after('a', post)
                life.engine.check_observed = lambda *args, **kwargs: dict(decision='need_approval', check_receipt=receipt)
                with self.assertRaises(ValueError):life.frames.accept(request)
                self.assertFalse(life.engine.approvals)
                self.assertEqual(life.actions['a']['status'], 'executor_gate_failed')

    def test_completed_notification_cannot_downgrade_deny(self):
        with lifecycle('deny') as life:
            request, post = prepare(life)
            life.after('a', post)
            self.assertFalse(life.frames.accept(request)['allowed'])
            with self.assertRaisesRegex(ValueError, 'unapproved'):
                notice(life)
            self.assertEqual(life.actions['a']['status'], 'denied')

    def test_late_native_permission_callback_cannot_return_the_unwrapped_command(self):
        with lifecycle() as life:
            request, post = prepare(life)
            life.frames.accept(request)
            with self.assertRaises(ValueError):life.approve('a', 'Bash', post['tool_input'])

    def test_unresolved_session_finish_invalidates_a_late_frame(self):
        with lifecycle() as life:
            request, post = prepare(life)
            life.after('a', post)
            self.assertEqual(life.finish()[0]['status'], 'unresolved')
            with self.assertRaises(ValueError):
                life.frames.accept(request)
            self.assertFalse(life.engine.checked)

    def test_pending_background_gate_is_not_complete_before_allocation_is_observed(self):
        with lifecycle() as life:
            prepare(life)
            self.assertTrue(life.pending_background())
            life.finish()
            self.assertFalse(life.pending_background())

    def test_background_identity_cannot_cross_actions_or_sessions(self):
        with lifecycle() as life:
            request, post = prepare(life)
            life.after('a', post)
            _, other = prepare(life, 'b')
            with self.assertRaises(ValueError):
                life.after('b', dict(other, tool_response={'backgroundTaskId': 'bg-a'}))
            with self.assertRaises(ValueError):
                life.observe_native(dict(type='system', subtype='task_notification', session_id='other',
                                         task_id='bg-a', tool_use_id='a', status='completed'))
            self.assertIn(request['ticket'], life.frames.pending)

    def test_foreground_success_still_requires_a_completed_guard_check(self):
        with lifecycle() as life:
            request, post = prepare(life, background=False)
            with self.assertRaisesRegex(ValueError, 'unapproved'):
                life.after('a', dict(post, tool_response={'stdout': 'claims execution'}))
            self.assertNotIn(request['ticket'], life.frames.pending)

    def test_foreground_task_notifications_do_not_create_pending_background_work(self):
        with lifecycle() as life:
            request, post = prepare(life, background=False)
            life.observe_native(dict(type='system', subtype='task_started', session_id='s', task_id='fg-a',
                                     tool_use_id='a', task_type='local_bash', is_backgrounded=False))
            life.frames.accept(request)
            life.after('a', dict(post, tool_response={'stdout': 'done'}))
            notice(life, task_id='fg-a')
            self.assertFalse(life.pending_background())
            self.assertEqual(life.actions['a']['status'], 'executed')


if __name__ == '__main__':
    unittest.main()
