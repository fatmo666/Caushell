"""Agent-failure handoff fixtures: no Docker, native client, or model request."""
import json
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from caushell_tb import harbor_agent
from harbor.agents.installed.base import NonZeroAgentExitCodeError
from harbor.models.task.verifier_mode import VerifierEnvironmentMode
from harbor.trial.single_step import SingleStepTrial


class NativeAgentOutcomeTests(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, terminal, native_result):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = root / 'agent'
            logs.mkdir()
            agent = object.__new__(harbor_agent.TaskFaithfulClaude)
            agent.logs_dir = logs
            agent.remote_settings = '/private/settings'
            agent.faithful = dict(
                mode='local', local_model_launch_authorized=True, docker='unused',
                image_id='fixture', assets='unused', asset_mount='/private/assets',
                commands=dict(observer=['observer']), agent_user=None,
                state_dir='/private/session', agent_timeout=30, host_workdir=tmp,
                host_guard='unused-guard', guard_config='unused-config',
                provider={}, model='fixture-model', task_config_sha256='fixture-task')
            environment = SimpleNamespace(
                _run_docker_compose_command=AsyncMock(return_value=SimpleNamespace(stdout='fixture')),
                exec=AsyncMock(return_value=SimpleNamespace(return_code=0,
                    stdout='uid=1000\nCAUSHELL_CONTEXT\0/home/tester\0/usr/bin:/bin\0/work\0')),
                _merge_env=lambda _: {})
            closed = []
            model = SimpleNamespace(stopped=threading.Event(), close=lambda: closed.append('model'))
            guard = SimpleNamespace(close=lambda: closed.append('guard'))
            lifecycle = SimpleNamespace(close=lambda: closed.append('lifecycle'))
            output = dict(terminal=terminal, result=native_result, actions=[], confirmations=0)

            def native_loop(folder, *_args, **_kwargs):
                (folder / 'claude.stdout.jsonl').write_text(json.dumps(native_result) + '\n')
                return output

            recorded = []
            order = []
            trial = SimpleNamespace(
                result=SimpleNamespace(agent_result=None, agent_execution=SimpleNamespace(finished_at=None)),
                task=SimpleNamespace(instruction='fixture', config=SimpleNamespace(agent=SimpleNamespace(user=None))),
                _agent_timeout_sec=30, _load_trajectory=None,
                _record_exception=recorded.append, _now=lambda: 'finished',
                _upload_agent_logs=AsyncMock(), _collect_artifacts=AsyncMock(),
                _stop_agent_environment=AsyncMock(), _sync_agent_output=AsyncMock())

            async def phase(**_kwargs):
                await agent.run('fixture', environment, None)

            async def verifier():
                # The actual Harbor control flow must still reach verification
                # after its recoverable agent failure and our evidence cleanup.
                self.assertEqual(closed, ['model', 'lifecycle', 'guard'])
                order.append('verifier')
                trial.result.reward = 1

            trial._run_agent_phase = phase
            trial._run_agent = lambda: SingleStepTrial._run_agent(trial)
            trial._run_verifier = verifier
            with patch.object(harbor_agent, 'validate_container'), \
                 patch.object(harbor_agent.subprocess, 'check_output', return_value='[{"Config":{"Env":[]}}]'), \
                 patch.object(harbor_agent.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stderr='')), \
                 patch.object(harbor_agent, 'ExternalEngine', return_value=guard), \
                 patch.object(harbor_agent, 'Lifecycle', return_value=lifecycle), \
                 patch.object(harbor_agent, 'Provider', return_value=model), \
                 patch.object(harbor_agent.native_loop, 'run', side_effect=native_loop), \
                 patch('harbor.trial.single_step.resolve_task_verifier_mode', return_value=VerifierEnvironmentMode.SHARED):
                await SingleStepTrial._run(trial)
            self.assertEqual(order, ['verifier'])
            self.assertEqual(trial.result.reward, 1)
            self.assertEqual(json.loads((root / 'control/result.json').read_text()), output)
            self.assertTrue((logs / 'claude-code.txt').exists())
            self.assertTrue((root / 'control/workspace-capture.json').exists())
            outcome = json.loads((root / 'control/native-outcome.json').read_text())
            self.assertEqual(outcome['success'], not recorded)
            events = [json.loads(line) for line in (root / 'control/events.jsonl').read_text().splitlines()]
            self.assertEqual(events[-1]['kind'], 'agent_phase_finished')
            return recorded

    async def test_semantic_native_error_survives_success_subtype_and_keeps_verifier(self):
        errors = await self.exercise('agent_error', dict(
            type='result', subtype='success', is_error=True,
            terminal_reason='api_error', api_error_status=503))
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], NonZeroAgentExitCodeError)

    async def test_successful_native_completion_has_no_agent_exception(self):
        self.assertEqual(await self.exercise('completed', dict(
            type='result', subtype='success', is_error=False)), [])

    async def test_unfinished_session_cannot_become_success_from_an_earlier_turn(self):
        for terminal in ['process_exit', 'timeout', 'budget_exhausted', 'controller_error']:
            with self.subTest(terminal=terminal):
                errors = await self.exercise(terminal, dict(type='result', is_error=False))
                self.assertEqual(len(errors), 1)
                self.assertIsInstance(errors[0], NonZeroAgentExitCodeError)

    async def test_completed_label_requires_a_complete_successful_native_result(self):
        for native in [None, {}, dict(type='other', is_error=False),
                       dict(type='result'), dict(type='result', is_error=True)]:
            with self.subTest(native=native):
                errors = await self.exercise('completed', native)
                self.assertEqual(len(errors), 1)
                self.assertIsInstance(errors[0], NonZeroAgentExitCodeError)


if __name__ == '__main__':
    unittest.main()
