"""Real private FD/filesystem transport, synthetic native identity fixtures.

Never launches Git, a candidate command, a benchmark case, or a model. The
fixture owns the files for the duration of each check. Its attestation is not a
claim about an installed Git executable. Run explicitly with CAUSHELL_TEST_HOST.
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
class GitHostTests(unittest.TestCase):
    def test_private_layout_content_integrity_environment_and_authority(self):
        with tempfile.TemporaryDirectory(prefix='git-host-') as tmp:
            root = Path(tmp).resolve()
            config = root / 'policy.yaml'
            config.write_text('version: 1\n')
            native = root / 'system-gitconfig'
            (root/'.git').mkdir()
            (root/'.git/config').write_text('')
            native.write_text('')
            marker = root / 'never-execute'
            layout = root / 'layout.json'
            layout.write_text(json.dumps({'git': dict(variant='git_2_39_5',
                system_config=str(native), configuration_snapshot_held=True)}))
            pip_layout = root / 'empty-pip.json'
            pip_layout.write_text('{}')

            def check(*, private=True, bad_hash=False, complete=True, data=None, identity=True, missing=None):
                if data is not None:
                    native.write_text(data)
                parent, child = socket.socketpair()
                observer = subprocess.Popen([HOST, 'observe'], stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                greeting = json.loads(observer.stdout.readline())
                self.assertEqual(greeting['observer_protocol'], 1)
                argv = [HOST, 'serve', str(child.fileno()), str(config), str(root / str(uuid.uuid4()))]
                if private:
                    argv.extend([str(pip_layout), str(layout)])
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
                    exports = dict(PATH='/usr/bin:/bin', HOME=str(root/'home'), LC_ALL='C')
                    exports = {k: v for k, v in exports.items() if not k.startswith('CAUSHELL_')}
                    request = dict(intent='judge_only', session_id=str(uuid.uuid4()),
                                   command='git ls-files', shell_kind='bash',
                                   home=str(root / 'home'), workspace_root=str(root),
                                   shell_state_before=dict(cwd=str(root),
                                       observability=dict(variables='exported_only' if complete else 'unknown',
                                                          aliases='unknown', functions='unknown'),
                                       variables=[dict(name=k, exported=True, value=dict(kind='exact_scalar', value=v))
                                                  for k, v in exports.items()] if complete else []),
                                   runtime=dict(runtime_name='git-host-fixture', tool_name='Bash',
                                       shell_runtime_capabilities={k: False for k in (
                                           'persists_cwd', 'persists_variables', 'persists_exported_environment',
                                           'persists_aliases', 'persists_functions', 'persists_positionals')}))
                    plan = rpc('execution_frame_plan', dict(request=request, executor_instance_id='private-fixture'))
                    request['shell_state_before']['execution_frame'] = dict(
                        binding=plan['binding'], pathname=None,
                        native_variants={'git': 'git_2_39_5'} if identity else {},
                        environment=[dict(name=k, value=dict(status='present', value=exports[k]) if k in exports
                                          else dict(status='absent'))
                                     for k in plan['requirements']['environment_names'] if k!=missing])
                    # A tool-payload lookalike cannot replace the private host
                    # constructor input, even if the wire parser ignores it.
                    request['git_runtime_layout'] = json.loads(layout.read_text())
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
            self.assertEqual(check(identity=False)['decision'], 'need_approval')
            # Git uses named exports, not Pip's whole-environment closure.
            self.assertEqual(check(complete=False)['decision'], 'allow')
            self.assertEqual(check(complete=False, missing='GIT_DIR')['decision'], 'need_approval')
            self.assertEqual(check(bad_hash=True)['decision'], 'need_approval')
            self.assertEqual(check(data='[core]\nfsmonitor=rm -rf /\n')['decision'], 'deny')
            self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()
