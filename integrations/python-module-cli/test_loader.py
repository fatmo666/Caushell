import copy
import os
from pathlib import Path
import tempfile
import time
import unittest
from loader import (ENVIRONMENT, IncompleteIdentity, NamespaceLease, attest,
                    digest, file_digest, grant_permission, directory_observation)


class LoaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.work = self.root / "work"
        self.runtime = self.root / "runtime"
        self.work.mkdir(); self.runtime.mkdir()
        (self.work / "a.py").write_text("this source is never imported or executed")
        (self.runtime / "python3").write_text("pinned runtime")
        (self.runtime / "python3").chmod(0o755)
        (self.runtime / "py_compile.py").write_text("pinned registered CLI")
        self.query = dict(binding=dict(protocol=1, executor_instance_id="owner", session_id="s", sequence_no=1,
                         runtime_name="test", shell_kind="bash", cwd=str(self.work), command_sha256="a"*64),
                         node_id="module-node", runtime="python", module="py_compile",
                         command="python3 -m py_compile a.py", cwd=str(self.work))
        self.manifest = dict(schema="caushell.cpython-module-cli/v1", platform="linux", version=[3,12,3],
                             image_digest="sha256:"+"b"*64, executable=str(self.runtime/"python3"),
                             files={str(p):file_digest(p) for p in self.runtime.iterdir()},
                             module_origins={"py_compile":str(self.runtime/"py_compile.py")},
                             account=dict(uid=1000,euid=1000,gid=1000,egid=1000),
                             search_roots=[str(self.runtime)], site_directories=[], account_home=str(self.root/"absent-home"), user_site=str(self.root/"absent-home/.local/lib/python3.12/site-packages"),
                             reserved_import_names=["os","sys","py_compile","importlib"],
                             extension_suffixes=[".so"],absent_configuration=[str(self.runtime/"pyvenv.cfg")])
        self.execution = dict(namespace_id="ns",binding=self.query["binding"],node_id="module-node",cwd=str(self.work),
                              executable=self.manifest["executable"],argv=["python3","-m","py_compile","a.py"],
                              account=self.manifest["account"], environment_complete=True,
                              environment={name:dict(status="absent") for name in ENVIRONMENT})
        self.execution["environment"]["PATH"] = dict(status="present", value=str(self.runtime))
        self.lease = NamespaceLease("ns",self.manifest["image_digest"],time.monotonic()+60,lambda namespace,image:namespace=="ns" and image==self.manifest["image_digest"])

    def tearDown(self):self.temp.cleanup()
    def identity(self):return attest(self.query,self.manifest,self.execution,self.lease)[0]

    def test_pinned_origin_returns_facts_without_permission(self):
        identity=self.identity()
        self.assertEqual(identity["files"],self.manifest["files"])
        self.assertNotIn("grant_id",identity)
        with self.assertRaises(IncompleteIdentity):grant_permission(identity,"g",set())
        grant=grant_permission(identity,"g",{digest(self.manifest)})
        self.assertEqual(grant["identity_sha256"],digest(identity))
        self.assertFalse((self.work/"__pycache__").exists())

    def test_module_package_native_and_dependency_shadowing_are_incomplete(self):
        for name in ("py_compile.py","py_compile.pyc","py_compile.so","os.py","sitecustomize.py"):
            p=self.work/name;p.write_text("shadow")
            with self.assertRaises(IncompleteIdentity,msg=name):self.identity()
            p.unlink()
        (self.work/"py_compile").mkdir()
        with self.assertRaises(IncompleteIdentity):self.identity()

    def test_digest_account_lookup_and_context_cannot_be_substituted(self):
        original=copy.deepcopy(self.execution)
        for field,value in (("namespace_id","other"),("cwd",str(self.runtime)),("executable",str(self.work/"python")),("account",dict(uid=0,euid=0,gid=0,egid=0))):
            self.execution[field]=value
            with self.assertRaises(IncompleteIdentity,msg=field):self.identity()
            self.execution=copy.deepcopy(original)
        (self.runtime/"py_compile.py").write_text("changed")
        with self.assertRaises(IncompleteIdentity):self.identity()

    def test_unknown_loader_environment_and_lease_expiry_remain_incomplete(self):
        self.execution["environment"]["PYTHONPATH"]=dict(status="unknown")
        with self.assertRaises(IncompleteIdentity):self.identity()
        self.execution["environment"]["PYTHONPATH"]=dict(status="absent")
        self.execution["environment"]["LD_PRELOAD"]=dict(status="present",value="/tmp/loader.so")
        with self.assertRaises(IncompleteIdentity):self.identity()
        self.execution["environment"]["LD_PRELOAD"]=dict(status="absent")
        self.lease=NamespaceLease("ns",self.manifest["image_digest"],time.monotonic()-1,lambda *_:True)
        with self.assertRaises(IncompleteIdentity):self.identity()

    def test_site_customizers_and_pth_require_further_loading_contracts(self):
        self.manifest["site_directories"]=[str(self.runtime)]
        (self.runtime/"custom.pth").write_text("import arbitrary_startup")
        with self.assertRaises(IncompleteIdentity):self.identity()
        self.execution["argv"]=["python3","-I","-S","-B","-m","py_compile","a.py"]
        self.assertEqual(self.identity()["module_file"],self.manifest["module_origins"]["py_compile"])

    def test_runtime_configuration_and_directory_changes_are_observed(self):
        before,_=directory_observation(self.work)
        (self.work/"another.txt").write_text("metadata only")
        after,_=directory_observation(self.work)
        self.assertNotEqual(before["sha256"],after["sha256"])
        (self.runtime/"pyvenv.cfg").write_text("runtime override")
        with self.assertRaises(IncompleteIdentity):self.identity()


class AdditionalBoundaryTests(unittest.TestCase):
    setUp = LoaderTests.setUp
    tearDown = LoaderTests.tearDown
    identity = LoaderTests.identity

    def test_known_home_without_user_site_is_a_valid_plain_startup(self):
        self.execution["environment"]["HOME"]=dict(status="present",value=str(self.root/"new-home"))
        self.assertEqual(self.identity()["module_file"],self.manifest["module_origins"]["py_compile"])

    def test_actual_home_controls_user_site_and_elf_controls_ignore_python_flags(self):
        home=self.root/"other-home"
        (home/".local/lib/python3.12/site-packages").mkdir(parents=True)
        self.execution["environment"]["HOME"]=dict(status="present",value=str(home))
        with self.assertRaises(IncompleteIdentity):self.identity()
        self.execution["argv"]=["python3","-I","-S","-B","-m","py_compile","a.py"]
        self.assertEqual(self.identity()["module_file"],self.manifest["module_origins"]["py_compile"])
        self.execution["environment"]["LD_AUDIT"]=dict(status="present",value="/tmp/audit.so")
        with self.assertRaises(IncompleteIdentity):self.identity()

    def test_unknown_options_module_rebinding_and_missing_environment_are_incomplete(self):
        self.execution["argv"]=["python3","-X","arbitrary","-m","py_compile","a.py"]
        with self.assertRaises(IncompleteIdentity):self.identity()
        self.execution["argv"]=["python3","-m","other","a.py"]
        with self.assertRaises(IncompleteIdentity):self.identity()
        self.execution["argv"]=["python3","-m","py_compile","a.py"]
        self.execution["environment_complete"]=False
        with self.assertRaises(IncompleteIdentity):self.identity()

class ProgramLookupTests(unittest.TestCase):
    setUp = LoaderTests.setUp
    tearDown = LoaderTests.tearDown
    identity = LoaderTests.identity

    def test_launcher_override_is_not_ignored_by_isolated_mode(self):
        self.execution["argv"] = ["python3", "-I", "-S", "-m", "py_compile", "a.py"]
        self.execution["environment"]["__PYVENV_LAUNCHER__"] = dict(status="present", value="/tmp/alternate/python")
        with self.assertRaises(IncompleteIdentity):
            self.identity()

    def test_shell_hash_and_cpython_path_lookup_must_agree(self):
        (self.work / "python3").write_text("different interpreter")
        (self.work / "python3").chmod(0o755)
        self.execution["environment"]["PATH"] = dict(status="present", value=str(self.work) + ":" + str(self.runtime))
        with self.assertRaises(IncompleteIdentity):
            self.identity()

    def test_original_executable_spelling_cannot_add_venv_configuration(self):
        alias = self.work / "renamed-python"
        alias.symlink_to(self.runtime / "python3")
        self.execution["argv"][0] = str(alias)
        self.assertEqual(self.identity()["executable"], self.manifest["executable"])
        (self.work / "pyvenv.cfg").write_text("home = /tmp/alternate")
        with self.assertRaises(IncompleteIdentity):
            self.identity()

if __name__ == "__main__":
    unittest.main()
