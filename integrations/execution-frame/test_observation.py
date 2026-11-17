import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from observation import collect, decode, ObservationUnavailable, _declaration

HERE = Path(__file__).resolve().parent


class PausedBash:
    """A real owning-executor fixture; a second probe Shell is never sampled."""
    def __init__(self, home, cwd, setup=""):
        self.home, self.cwd, self.setup = str(home), str(cwd), setup
        self.process = None

    def capture(self, nonce, names, variables=(), natives=()):
        capture_name='caushell_frame_capture_extended' if natives else 'caushell_frame_capture_plan'
        group=[str(len(names)),str(len(variables)),str(len(natives)),*names,*variables,*natives] if natives else [str(len(names)),*names,*variables]
        script = (". " + shlex.quote(str(HERE / "capture.bash")) + "\n" + self.setup
                  + '\n'+capture_name+' "$@" || exit "$?"\nbuiltin printf "caushell-capture-done\\0%s\\0" "$1"\nIFS= builtin read -r gate || :\n')
        self.process = subprocess.Popen(
            [os.environ.get('CAUSHELL_TEST_BASH', '/bin/bash'), "--noprofile", "--norc", "-c", script, "owned-frame", nonce, *group],
            cwd=self.cwd, env=dict(PATH="/usr/bin:/bin", HOME=self.home, LC_ALL="C"),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        fields = []
        for _ in range(65536):
            value = bytearray()
            while True:
                byte = self.process.stdout.read(1)
                if not byte:
                    raise ObservationUnavailable("owning executor ended before capture")
                if byte == b"\0":
                    break
                value.extend(byte)
            fields.append(bytes(value))
            if len(fields)>=2 and fields[-2:]==[b'caushell-capture-done',nonce.encode()]:
                return b"\0".join(fields[:-2]) + b"\0"
        raise ObservationUnavailable('capture fixture exceeded field budget')

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
    def typed_capture(self, setup, variables):
        p=plan([]);p['requirements']['variable_names']=variables
        with tempfile.TemporaryDirectory() as d:
            owner=PausedBash(d,d,setup)
            try:return collect(p,owner.capture)
            finally:owner.close()

    def test_sparse_array_bytes_and_empty_elements_are_owned_facts(self):
        frame=self.typed_capture('declare -a slots=([2]="a b" [7]=$\'line\\nnext\' [9]="")',['slots'])
        observed={x['name']:x['value'] for x in frame['variable_values']}
        self.assertEqual(observed['slots'],dict(kind='indexed_array',elements=[[2,'a b'],[7,'line\nnext'],[9,'']],complete=True))
        self.assertEqual(frame['variables'][0]['value'],dict(status='unknown'))
        self.assertEqual(frame['environment'],[])

    def test_declaration_parser_never_evaluates_expansions_or_executable_indices(self):
        for text in ['declare -a slots=([$(touch marker)]="data")',
                     'declare -a slots=([1+2]="data")',
                     'declare -- slots="$(touch marker)"',
                     'declare -n slots="other[$(touch marker)]"',
                     'declare -a slots=([1]="one" [1]="two")',
                     'declare -ai slots=([1]="3")',
                     'declare -r slots="outside.data"',
                     'declare -ar slots=([1]="outside.data")',
                     'declare -nr slots="other"']:
            self.assertIn(_declaration('slots','declaration',text)['kind'],('unknown','unsupported'),text)
        self.assertEqual(_declaration('slots','declaration',r'declare -- slots="\$(not_code)"'),
                         dict(kind='scalar',value='$(not_code)',integer=False))

    def test_unrepresentable_or_oversized_declarations_remain_unknown(self):
        self.assertEqual(_declaration('slots','declaration',r"declare -a slots=([0]=$'\377')"),dict(kind='unknown'))
        elements=' '.join(f'[{i}]="x"' for i in range(257))
        self.assertEqual(_declaration('slots','declaration','declare -a slots=('+elements+')'),dict(kind='unknown'))

    def test_actual_nameref_chain_is_captured_without_flattening_or_export(self):
        bash=os.environ.get('CAUSHELL_TEST_BASH','/bin/bash')
        if subprocess.run([bash,'-c','declare -n ref=target'],capture_output=True).returncode:
            self.skipTest('nameref requires Bash 4.3 or later; also tested in Linux Bash')
        frame=self.typed_capture('value="safe.data"; declare -n ref=value; declare -n outer=ref',['outer'])
        values={x['name']:x['value'] for x in frame['variable_values']}
        self.assertEqual(values['outer'],dict(kind='name_reference',target='ref'))
        self.assertEqual(values['ref'],dict(kind='name_reference',target='value'))
        self.assertEqual(values['value'],dict(kind='scalar',value='safe.data',integer=False))
        self.assertEqual(frame['environment'],[])

    def test_nameref_cycle_and_subscript_do_not_execute_during_capture(self):
        bash=os.environ.get('CAUSHELL_TEST_BASH','/bin/bash')
        if subprocess.run([bash,'-c','declare -n ref=target'],capture_output=True).returncode:
            self.skipTest('nameref requires Bash 4.3 or later; also tested in Linux Bash')
        cycle=self.typed_capture('declare -n first=second; declare -n second=first',['first'])
        self.assertEqual(cycle['variable_values'],[dict(name='first',value=dict(kind='unknown'))])
        with tempfile.TemporaryDirectory() as d:
            p=plan([]);p['requirements']['variable_names']=['ref']
            owner=PausedBash(d,d,'declare -n ref=\'data[$(touch marker)]\'')
            try:frame=collect(p,owner.capture)
            finally:owner.close()
            self.assertEqual(frame['variable_values'][0]['value'],dict(kind='unsupported'))
            self.assertFalse((Path(d)/'marker').exists())

    def test_associative_declarations_are_keyed_facts_without_an_order_claim(self):
        bash=os.environ.get('CAUSHELL_TEST_BASH','/bin/bash')
        if subprocess.run([bash,'-c','declare -A table'],capture_output=True).returncode:
            self.skipTest('associative arrays require Bash 4 or later; also tested in Linux Bash')
        frame=self.typed_capture('declare -A table=(["space key"]="value data" [other]="two")',['table'])
        value=frame['variable_values'][0]['value']
        self.assertEqual(value['kind'],'associative_array')
        self.assertEqual(dict(value['elements']),{'space key':'value data','other':'two'})
        self.assertNotIn('complete',value)

    def test_integer_attribute_is_observed_without_freezing_volatile_values(self):
        p = plan([])
        p['requirements']['variable_names'] = ['SECONDS', 'RANDOM', 'number', 'plain', 'ARRAY', 'empty']
        with tempfile.TemporaryDirectory() as d:
            owner = PausedBash(d, d, 'declare -i number=42; plain=42; declare -ai ARRAY=(1); declare -i empty')
            try:
                frame = collect(p, owner.capture)
            finally:
                owner.close()
        self.assertEqual(set(frame['integer_variables']), {'SECONDS', 'RANDOM', 'number'})
        values = {v['name']:v['value'] for v in frame['variables']}
        self.assertEqual(values['SECONDS'], dict(status='unknown'))
        self.assertEqual(values['number'], dict(status='present', value='42'))
        with tempfile.TemporaryDirectory() as d:
            owner = PausedBash(d, d, 'unset SECONDS; SECONDS=untrusted')
            try:
                frame = collect(p, owner.capture)
            finally:
                owner.close()
        self.assertNotIn('SECONDS', frame.get('integer_variables', []))

    def test_integer_protocol_is_bounded_and_legacy_capture_remains_compatible(self):
        p = plan([])
        p['requirements']['variable_names'] = ['number']
        with tempfile.TemporaryDirectory() as d:
            owner = PausedBash(d, d, 'declare -i number=42')
            try:
                raw = owner.capture('0'*32, (), ('number',))
            finally:
                owner.close()
        self.assertEqual(decode(p, '0'*32, raw)['integer_variables'], ['number'])
        with self.assertRaises(ObservationUnavailable):
            decode(p, '0'*32, raw.replace(b'number\x001\x00', b'number\x002\x00'))
        legacy = raw.split(b'caushell-shell-declarations-v1\0',1)[0].replace(b'caushell-shell-scalars-v2', b'caushell-shell-scalars-v1').replace(b'number\x001\x00', b'number\x00')
        self.assertNotIn('integer_variables', decode(p, '0'*32, legacy))

    def test_local_scalars_have_their_own_partial_channel(self):
        p = plan(["LOCAL", "EMPTY", "ARRAY"])
        p["requirements"]["variable_names"] = ["LOCAL", "EMPTY", "ARRAY", "MISSING", "RANDOM"]
        with tempfile.TemporaryDirectory() as d:
            owner = PausedBash(d, d, 'LOCAL=private; EMPTY=""; declare -a ARRAY=(one two)')
            try:
                frame = collect(p, owner.capture)
            finally:
                owner.close()
        env = {v["name"]:v["value"] for v in frame["environment"]}
        vals = {v["name"]:v["value"] for v in frame["variables"]}
        self.assertEqual(env["LOCAL"], dict(status="absent"))
        self.assertEqual(vals["LOCAL"], dict(status="present", value="private"))
        self.assertEqual(vals["EMPTY"], dict(status="present", value=""))
        self.assertEqual(vals["MISSING"], dict(status="absent"))
        self.assertEqual(vals["ARRAY"], dict(status="unknown"))
        self.assertEqual(vals["RANDOM"], dict(status="unknown"))

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
    def test_real_local_values_resolve_argv_without_authorizing_external_writes(self):
        for command, setup, expected in [
            ('printf safe > "$DEST"', 'DEST=local.data', 'allow'),
            ('printf safe > "$DEST"', 'DEST=/opt/shared.data', 'need_approval'),
            ('printf safe > "$PWD/out"', 'PWD=/opt', 'need_approval'),
            ('rm "$DEST"', 'DEST=local.data', 'need_approval'),
            ('rm -rf /; printf "%s" "$DEST"', 'DEST=local.data', 'deny'),
            ('printf safe > "$DEST"', 'declare -a DEST=(local.data)', 'allow'),
        ]:
            request = self.request(command, command + setup)
            frame, owner = self.observed(request, setup)
            try:
                request['shell_state_before']['execution_frame'] = frame
                self.assertEqual(self.rpc('check', request)['decision'], expected, (command, setup))
            finally:
                owner.close()
        self.assertFalse((self.work/'local.data').exists())

    def test_compound_facts_reach_the_guard_without_running_pending_actions(self):
        # Compound argv facts do not certify Git's configuration installation.
        # Use a real explicit source for the positive case and keep the missing
        # layout negative case; pending git/diff actions are never executed.
        git_system=self.root/'git-system.conf';git_system.write_text('')
        for command,setup,expected in [
            ('printf data > "${dest[3]}"','declare -a dest=([3]=inside.data)','allow'),
            ('printf data > "${dest[3]}"','declare -a dest=([3]=/opt/outside.data)','need_approval'),
            ('rm -- "${dest[3]}"','declare -a dest=([3]=input.data)','need_approval'),
            ('rm -rf /; printf "%s" "${dest[@]}"','declare -a dest=(inside.data)','deny'),
            ('printf data > "${dest[3]}"','declare -ai dest=([3]=7)','need_approval'),
            ('mkdir -- "${dest[@]}"','declare -a dest=([2]=first-dir [7]=second-dir)','allow'),
            ('mkdir -- "${dest[@]}"','declare -a dest=([2]=first-dir [7]=/opt/outside-dir)','need_approval'),
            ('curl -q --noproxy \'*\' "${flags[@]}" -I https://fixture.invalid/',
             'declare -a flags=(--cacert input.data)','allow'),
            ('git --no-optional-locks -C . "${verb[@]}" -- input.data','declare -a verb=(diff)','need_approval'),
            ('git --no-optional-locks -C . "${verb[@]}" -- input.data',
             'declare -a verb=(diff); export GIT_CONFIG_SYSTEM='+shlex.quote(str(git_system)),'allow'),
        ]:
            request=self.request(command,hashlib.sha256((command+setup).encode()).hexdigest())
            frame,owner=self.observed(request,setup)
            try:
                request['shell_state_before']['execution_frame']=frame
                self.assertEqual(self.rpc('check',request)['decision'],expected,(command,frame))
            finally:owner.close()
        self.assertFalse((self.work/'inside.data').exists())

    def test_nameref_and_associative_values_reach_the_guard_with_safe_boundaries(self):
        bash=os.environ.get('CAUSHELL_TEST_BASH','/bin/bash')
        if subprocess.run([bash,'-c','declare -n ref=target; declare -A table'],capture_output=True).returncode:
            self.skipTest('full compound fixture requires Bash 4.3 or later')
        for command,setup,expected in [
            ('printf data > "$outer"','dest=inside.data; declare -n ref=dest; declare -n outer=ref','allow'),
            ('printf data > "${outer[3]}"','declare -a dest=([3]=inside.data); declare -n outer=dest','allow'),
            ('printf data > "${table[destination]}"','declare -A table=([destination]=inside.data)','allow'),
            ('printf data > "$outer"','dest=/opt/outside.data; declare -n outer=dest','need_approval'),
            ('rm "$outer"','dest=input.data; declare -n outer=dest','need_approval'),
            ('printf data > "$outer"','declare -n outer=ref; declare -n ref=outer','need_approval'),
            ('dest=inside.data; printf data > "$dest"','declare -u dest=previous','need_approval'),
            ('dest=inside.data; printf data > "$dest"','declare -r dest=/opt/outside.data','need_approval'),
            ('printf "%s" "$outer"',
             f"declare -a dest=(); declare -n outer='dest[$(touch {self.work}/index-marker)]'",'need_approval'),
            ('rm -rf /; printf "%s" "$outer"',
             f"declare -a dest=(); declare -n outer='dest[$(touch {self.work}/index-marker)]'",'deny'),
        ]:
            request=self.request(command,command+setup);frame,owner=self.observed(request,setup)
            try:
                request['shell_state_before']['execution_frame']=frame
                self.assertEqual(self.rpc('check',request)['decision'],expected,(command,frame))
            finally:owner.close()
        self.assertFalse((self.work/'inside.data').exists())
        self.assertFalse((self.work/'index-marker').exists())

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

    def test_apt_native_configuration_mode_and_resource_lifecycle(self):
        etc=self.root/"apt-config";etc.mkdir();(etc/"parts").mkdir()
        config=etc/"startup.conf"
        config.write_text('Dir::Etc "'+str(etc)+'"; Dir::Etc::Parts "parts"; Dir::Etc::main "main.conf";\n')
        setup="export APT_CONFIG="+shlex.quote(str(config))
        command="apt-get download fixture-package"
        request=self.request(command,"apt-frame")
        self.assertEqual(self.rpc("check",request)["decision"],"need_approval")
        frame,owner=self.observed(request,setup)
        try:
            self.assertIn("APT_CONFIG",[e["name"] for e in frame["environment"]])
            request["shell_state_before"]["execution_frame"]=frame
            self.assertEqual(self.rpc("check",request)["decision"],"allow")
        finally:owner.close()
        # A new config hook is observed afresh; an old complete result is not cached.
        hook=etc/"parts"/"50.conf";hook.write_text('DPkg::Pre-Invoke { "id"; };\n')
        request=self.request(command,"apt-hook")
        frame,owner=self.observed(request,setup)
        try:
            request["shell_state_before"]["execution_frame"]=frame
            self.assertEqual(self.rpc("check",request)["decision"],"need_approval")
        finally:owner.close()
        hook.unlink()
        # Download writes are authorized by the ordinary workspace policy.
        for command in ["apt-get -d install fixture-package","apt-get install fixture-package",
                        "apt-get download fixture-package; rm ./ordinary-file",
                        "apt-get download fixture-package; Rscript -e 1"]:
            request=self.request(command,command)
            frame,owner=self.observed(request,setup)
            try:
                request["shell_state_before"]["execution_frame"]=frame
                self.assertEqual(self.rpc("check",request)["decision"],"need_approval")
            finally:owner.close()
        # A symlink in a possible download output family cannot borrow directory authority.
        (self.work/"existing.deb").symlink_to("/opt/ungranted/target")
        request=self.request("apt-get download fixture-package","apt-link")
        frame,owner=self.observed(request,setup)
        try:
            request["shell_state_before"]["execution_frame"]=frame
            self.assertEqual(self.rpc("check",request)["decision"],"need_approval")
        finally:owner.close()
        self.assertEqual(list(self.work.glob("fixture-package*")),[])

    def test_observations_do_not_grant_write_execute_or_inline_authority(self):
        for command in ["touch /opt/ungranted/new-file","Rscript -e 'print(7)'","rm ./ordinary-file"]:
            request=self.request(command,command)
            frame,owner=self.observed(request)
            try:
                request["shell_state_before"]["execution_frame"]=frame
                self.assertEqual(self.rpc("check",request)["decision"],"need_approval")
            finally:owner.close()


if __name__=="__main__":unittest.main()
