import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from observation import collect, decode, ObservationUnavailable

HERE = Path(__file__).resolve().parent


class PausedBash:
    """A real owning-executor fixture; a second probe Shell is never sampled."""
    def __init__(self, home, cwd, setup=""):
        self.home, self.cwd, self.setup = str(home), str(cwd), setup
        self.process = None

    def capture(self, nonce, names):
        script = (". " + shlex.quote(str(HERE / "capture.bash")) + "\n" + self.setup
                  + '\ncaushell_frame_capture "$@" || exit "$?"\nIFS= builtin read -r gate || :\n')
        self.process = subprocess.Popen(
            ["/bin/bash", "--noprofile", "--norc", "-c", script, "owned-frame", nonce, *names],
            cwd=self.cwd, env=dict(PATH="/usr/bin:/bin", HOME=self.home, LC_ALL="C"),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        fields = []
        for _ in range(21 + 3 * len(names)):
            value = bytearray()
            while True:
                byte = self.process.stdout.read(1)
                if not byte:
                    raise ObservationUnavailable("owning executor ended before capture")
                if byte == b"\0":
                    break
                value.extend(byte)
            fields.append(bytes(value))
        return b"\0".join(fields) + b"\0"

    def close(self):
        if self.process:
            self.process.stdin.close()
            self.process.wait(timeout=5)
            self.process.stdout.close()
            stderr = self.process.stderr.read()
            self.process.stderr.close()
            if self.process.returncode:
                raise AssertionError((self.process.returncode, stderr))


def plan(names):
    return dict(binding=dict(protocol=1, executor_instance_id="owned-fixture", session_id="fixture",
                sequence_no=1, runtime_name="owned", shell_kind="bash", cwd="/unused",
                command_sha256=hashlib.sha256(b"never executed").hexdigest()),
                requirements=dict(environment_names=names, pathname=True))


class CollectorTests(unittest.TestCase):
    def capture(self, names, setup=""):
        with tempfile.TemporaryDirectory() as directory:
            owner=PausedBash(directory, directory, setup)
            try:
                return collect(plan(names), owner.capture)
            finally:
                owner.close()

    def test_exported_absent_empty_and_shell_local_are_distinct(self):
        frame=self.capture(["EXPORTED", "EMPTY", "MISSING", "LOCAL", "name"],
            'export EXPORTED=$\'line1\\nline2\'; export EMPTY=""; LOCAL=private; export name=not_shadowed')
        values={e["name"]:e["value"] for e in frame["environment"]}
        self.assertEqual(values["EXPORTED"],dict(status="present",value="line1\nline2"))
        self.assertEqual(values["EMPTY"],dict(status="present",value=""))
        self.assertEqual(values["MISSING"],dict(status="absent"))
        self.assertEqual(values["LOCAL"],dict(status="absent"))
        self.assertEqual(values["name"],dict(status="present",value="not_shadowed"))

    def test_shell_glob_state_includes_unexported_globignore(self):
        x=self.capture([], "shopt -s nullglob nocaseglob; GLOBIGNORE=skip.data")
        self.assertTrue(x["pathname"]["nullglob"])
        self.assertTrue(x["pathname"]["nocaseglob"])
        self.assertEqual(x["pathname"]["globignore"],dict(status="present",value="skip.data"))

    def test_capture_does_not_overwrite_requested_variable_names(self):
        x=self.capture(["declaration","name","gate"],"export declaration=first name=second gate=third")
        self.assertEqual([e["value"]["value"] for e in x["environment"]],["first","second","third"])

    def test_volatile_values_and_arrays_remain_unknown(self):
        x=self.capture(["RANDOM","_","ARRAY"],"declare -ax ARRAY=(one two)")
        self.assertTrue(all(e["value"]==dict(status="unknown") for e in x["environment"]))

    def test_partial_untrusted_and_cross_frame_captures_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            owner=PausedBash(d,d)
            try: raw=owner.capture("a"*32,("VALUE",))
            finally: owner.close()
            for data,nonce in [(raw[:-1],"a"*32),(raw,"b"*32),(raw+b"tail","a"*32),
                               (raw.replace(b"absent\0\0",b"absent\0invented\0",1),"a"*32)]:
                with self.assertRaises(ObservationUnavailable):decode(plan(["VALUE"]),nonce,data)

    def test_plan_bounds_names_and_no_default_ambient_fallback(self):
        for names in [["BAD[0]"],["X","X"],["X"]*129]:
            with self.assertRaises(ObservationUnavailable):collect(plan(names),lambda *_:b"")
        with self.assertRaises(ObservationUnavailable):collect(plan(["HOME"]),lambda *_:b"")


class GuardEndToEnd(unittest.TestCase):
    def setUp(self):
        self.binary=os.environ.get("CAUSHELL_TEST_BINARY")
        if not self.binary:self.skipTest("set CAUSHELL_TEST_BINARY to the separately built test binary")
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()
        self.work=self.root/"work";self.work.mkdir();self.home=self.root/"home";self.home.mkdir()
        (self.work/"input.data").write_text("safe fixture\n")
        config=self.root/"config.yaml";config.write_text("{}\n")
        self.runtime=subprocess.Popen([self.binary,"serve-stdio","--config",str(config),"--store",str(self.root/"store")],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.assertEqual(self.rpc("ping")["execution_frame_protocol"],1)

    def tearDown(self):
        if not hasattr(self,"runtime"):return
        self.runtime.stdin.close();self.runtime.wait(timeout=5)
        self.runtime.stdout.close();err=self.runtime.stderr.read();self.runtime.stderr.close()
        self.assertEqual(self.runtime.returncode,0,err)
        self.temp.cleanup()

    def rpc(self,kind,payload=None):
        q=dict(kind=kind)
        if payload is not None:q["payload"]=payload
        self.runtime.stdin.write(json.dumps(q).encode()+b"\n");self.runtime.stdin.flush()
        result=json.loads(self.runtime.stdout.readline())
        self.assertEqual(result["kind"],kind)
        return result["payload"]

    def request(self, command, session="owned-frame"):
        return dict(intent="judge_only",session_id=session,command=command,shell_kind="bash",
            shell_state_before=dict(cwd=str(self.work)),home=str(self.home),workspace_root=str(self.work),
            runtime=dict(runtime_name="executor-frame-test",tool_name="Bash",shell_runtime_capabilities=dict(
                persists_cwd=False,persists_variables=False,persists_exported_environment=False,
                persists_aliases=False,persists_functions=False,persists_positionals=False)))

    def observed(self,request,setup=""):
        p=self.rpc("execution_frame_plan",dict(request=request,executor_instance_id="paused-bash"))
        owner=PausedBash(self.home,self.work,setup)
        try:frame=collect(p,owner.capture)
        except BaseException:owner.close();raise
        return frame,owner

    def test_actual_frame_reduces_curl_and_glob_ask_without_running_them(self):
        for command in ["curl -I https://fixture.invalid/","md5sum *.data"]:
            request=self.request(command,command)
            self.assertEqual(self.rpc("check",request)["decision"],"need_approval")
            frame,owner=self.observed(request)
            try:
                request["shell_state_before"]["execution_frame"]=frame
                self.assertEqual(self.rpc("check",request)["decision"],"allow")
            finally:owner.close()
        self.assertEqual((self.work/"input.data").read_text(),"safe fixture\n")

    def test_frame_expiry_changed_configuration_and_deny(self):
        request=self.request("curl -I https://fixture.invalid/")
        frame,owner=self.observed(request)
        try:
            request["shell_state_before"]["execution_frame"]=frame
            self.assertEqual(self.rpc("check",request)["decision"],"allow")
        finally:owner.close()
        # Same frame cannot be replayed at a later sequence.
        self.assertEqual(self.rpc("check",request)["decision"],"need_approval")
        del request["shell_state_before"]["execution_frame"]
        self.assertEqual(self.rpc("check",request)["decision"],"need_approval")
        configuration=self.root/"curl-config";configuration.mkdir()
        (configuration/".curlrc").write_text("output = /opt/ungranted/result\n")
        frame,owner=self.observed(request,"export CURL_HOME="+shlex.quote(str(configuration)))
        try:
            request["shell_state_before"]["execution_frame"]=frame
            self.assertEqual(self.rpc("check",request)["decision"],"need_approval")
        finally:owner.close()
        request=self.request("rm -rf /","deny-frame")
        frame,owner=self.observed(request)
        try:
            frame["binding"]["command_sha256"]="0"*64
            request["shell_state_before"]["execution_frame"]=frame
            self.assertEqual(self.rpc("check",request)["decision"],"deny")
        finally:owner.close()

    def test_observations_do_not_grant_write_execute_or_inline_authority(self):
        for command in ["touch /opt/ungranted/new-file","Rscript -e 'print(7)'","rm ./ordinary-file"]:
            request=self.request(command,command)
            frame,owner=self.observed(request)
            try:
                request["shell_state_before"]["execution_frame"]=frame
                self.assertEqual(self.rpc("check",request)["decision"],"need_approval")
            finally:owner.close()


if __name__=="__main__":unittest.main()
