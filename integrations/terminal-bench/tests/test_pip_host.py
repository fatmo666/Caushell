"""Real private FD/filesystem transport, synthetic native identity fixtures.

Never launches pip, a candidate command, a benchmark case, or a model. The
fixture owns the files for the duration of each check. Its attestation is not a
claim about an installed interpreter. Run explicitly with CAUSHELL_TEST_HOST.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest
import uuid

HOST = os.environ.get('CAUSHELL_TEST_HOST')


@unittest.skipUnless(HOST, 'build trusted-filesystem-host and set CAUSHELL_TEST_HOST')
class PipHostTests(unittest.TestCase):
    def test_private_layout_content_integrity_environment_and_authority(self):
        with tempfile.TemporaryDirectory(prefix='pip-host-') as tmp:
            root = Path(tmp).resolve()
            config = root / 'policy.yaml'
            config.write_text('version: 1\n')
            native = root / 'pip.ini'
            native.write_text('[global]\nquiet=true\n')
            marker = root / 'never-execute'
            layout = root / 'layout.json'
            layout.write_text(json.dumps({'pip': dict(
                variant='pypa_pip_25_3_linux', prefix=str(root / 'venv'),
                account_home=str(root / 'home'), startup_read_only=True,
                configuration_snapshot_held=True,
                account=dict(uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(), egid=os.getegid()))}))

            def check(*, private=True, bad_hash=False, complete=True, data=None):
                if data is not None:
                    native.write_text(data)
                parent, child = socket.socketpair()
                observer = subprocess.Popen([HOST, 'observe'], stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                greeting = json.loads(observer.stdout.readline())
                self.assertEqual(greeting['observer_protocol'], 1)
                argv = [HOST, 'serve', str(child.fileno()), str(config), str(root / str(uuid.uuid4()))]
                if private:
                    argv.append(str(layout))
                host = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, pass_fds=[child.fileno()])
                child.close()
                errors = []

                def bridge():
                    try:
                        with parent.makefile('rwb', buffering=0) as wire:
                            while line := wire.readline():
                                observer.stdin.write(line)
                                observer.stdin.flush()
                                response = json.loads(observer.stdout.readline())
                                request = response['request']
                                if bad_hash and request['op'] == 'file' and request['path'] == str(native):
                                    response['value']['observation']['sha256'] = '0' * 64
                                wire.write(json.dumps(response).encode() + b'\n')
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    except Exception as exc:
                        errors.append(repr(exc))

                worker = threading.Thread(target=bridge, daemon=True)
                worker.start()

                def rpc(kind, payload):
                    host.stdin.write(json.dumps(dict(kind=kind, payload=payload)).encode() + b'\n')
                    host.stdin.flush()
                    line = host.stdout.readline()
                    if not line:
                        self.fail(host.stderr.read().decode())
                    response = json.loads(line)
                    self.assertEqual(response['kind'], kind, response)
                    return response['payload']

                try:
                    # This helper is the executor for this nonexecuting fixture.
                    # A complete export list includes all aliases, not only the
                    # finite dependencies requested by the normal frame planner.
                    exports = dict(os.environ, PIP_CONFIG_FILE=str(native), PYTHONDONTWRITEBYTECODE='1')
                    exports = {k: v for k, v in exports.items() if not k.startswith('CAUSHELL_')}
                    request = dict(intent='judge_only', session_id=str(uuid.uuid4()),
                                   command='pip show fixture-package', shell_kind='bash',
                                   home=str(root / 'home'), workspace_root=str(root),
                                   shell_state_before=dict(cwd=str(root),
                                       observability=dict(variables='exported_only' if complete else 'unknown',
                                                          aliases='unknown', functions='unknown'),
                                       variables=[dict(name=k, exported=True, value=dict(kind='exact_scalar', value=v))
                                                  for k, v in exports.items()] if complete else []),
                                   runtime=dict(runtime_name='pip-host-fixture', tool_name='Bash',
                                       shell_runtime_capabilities={k: False for k in (
                                           'persists_cwd', 'persists_variables', 'persists_exported_environment',
                                           'persists_aliases', 'persists_functions', 'persists_positionals')}))
                    plan = rpc('execution_frame_plan', dict(request=request, executor_instance_id='private-fixture'))
                    request['shell_state_before']['execution_frame'] = dict(
                        binding=plan['binding'], pathname=None,
                        native_variants={'pip': 'pypa_pip_25_3_linux'},
                        environment=[dict(name=k, value=dict(status='present', value=exports[k]) if k in exports
                                          else dict(status='absent'))
                                     for k in plan['requirements']['environment_names']])
                    # A tool-payload lookalike cannot replace the private host
                    # constructor input, even if the wire parser ignores it.
                    request['pip_runtime_layout'] = json.loads(layout.read_text())
                    response = rpc('check', request)
                    self.assertFalse(marker.exists())
                    return response
                finally:
                    host.stdin.close()
                    host.wait(timeout=10)
                    worker.join(timeout=10)
                    parent.close()
                    observer.stdin.close()
                    observer.wait(timeout=10)
                    host.stdout.close()
                    host.stderr.close()
                    observer.stdout.close()
                    observer.stderr.close()
                    self.assertFalse(worker.is_alive())
                    self.assertEqual(errors, [])

            self.assertEqual(check()['decision'], 'allow')
            self.assertEqual(check(private=False)['decision'], 'need_approval')
            self.assertEqual(check(complete=False)['decision'], 'need_approval')
            self.assertEqual(check(bad_hash=True)['decision'], 'need_approval')
            self.assertEqual(check(data='[global]\nlog=/outside/pip-host-log\n')['decision'], 'need_approval')
            literal = f'{root}/$(touch never-execute)'
            self.assertEqual(check(data=f'[global]\nlog={literal}\n')['decision'], 'allow')
            self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()
