"""Provisioning-only metadata capture in a trusted, immutable CPython image.

Run as the intended execution account with python -I -S -B capture.py IMAGE_SHA.
This inventories a registered CLI origin; it does not import that CLI or any task.
The deployment owner must establish and retain the namespace lease separately.
"""
import sys
assert sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
assert sys.version_info[:2] == (3, 12) and sys.platform == "linux"
import json
import os
from pathlib import Path
import pwd
import site
import sysconfig
# -I excludes the script's directory. This is a deployment-controlled helper.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from loader import file_digest

image = sys.argv[1]
assert image.startswith("sha256:") and len(image) == 71
executable = str(Path(sys.executable).resolve())
stdlib = str(Path(sysconfig.get_path("stdlib")).resolve())
module = str(Path(stdlib, "py_compile.py"))
# Runtime libraries/search roots are certified by the immutable deployment
# contract. Entry digests bind actual interpreter/module selection as well.
files = {p: file_digest(p) for p in (executable, module)}
absent = []
for directory in {str(Path(sys.executable).parent), str(Path(executable).parent)}:
    for path in (directory + "/pyvenv.cfg", str(Path(directory).parent / "pyvenv.cfg"),
                 executable + "._pth", directory + "/pybuilddir.txt"):
        if os.path.lexists(path):
            raise ValueError("unmodeled runtime path configuration: " + path)
        absent.append(path)
library = sysconfig.get_config_var("LDLIBRARY")
libdir = sysconfig.get_config_var("LIBDIR")
if library and libdir:
    candidate = str(Path(libdir, library).resolve()) + "._pth"
    if os.path.lexists(candidate):
        raise ValueError("unmodeled runtime library path configuration: " + candidate)
    absent.append(candidate)
from importlib.machinery import EXTENSION_SUFFIXES
home = pwd.getpwuid(os.geteuid()).pw_dir
manifest = dict(schema="caushell.cpython-module-cli/v1", platform=sys.platform,
                version=list(sys.version_info[:3]), image_digest=image,
                executable=executable, files=files,
                account=dict(uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(), egid=os.getegid()), account_home=home,
                module_origins={"py_compile": module},
                search_roots=list(sys.path[1:]), site_directories=site.getsitepackages(),
                user_site=home + "/.local/lib/python3.12/site-packages",
                absent_configuration=sorted(set(absent)),
                extension_suffixes=list(EXTENSION_SUFFIXES),
                reserved_import_names=sorted(sys.stdlib_module_names))
json.dump(manifest, sys.stdout, sort_keys=True)
print()
