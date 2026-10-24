"""Capture a deployment-controlled CPython runtime inventory without site startup."""
import sys

assert sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
assert sys.version_info[:2] == (3, 11) and sys.platform == 'linux'

import os
import pwd
import site
import sysconfig
import hashlib
import json
import _imp
from importlib.machinery import PathFinder, EXTENSION_SUFFIXES

MAX_BYTES = 134217728
files = {}
directories = {}
links = {}


def file(path):
    resolved = os.path.realpath(path)
    if os.path.islink(path):
        links[path] = os.readlink(path)
    if resolved in files:
        return
    before = os.stat(resolved)
    assert before.st_size <= 33554432
    with open(resolved, 'rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    after = os.stat(resolved)
    identity = lambda stat: (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
    assert identity(before) == identity(after)
    files[resolved] = dict(sha256=digest, size=before.st_size)
    assert len(files) <= 4096 and sum(f['size'] for f in files.values()) <= MAX_BYTES


def inventory(root):
    if root in directories:
        return
    assert os.path.realpath(root) == root
    for current, children, names in os.walk(root, followlinks=False):
        entries = []
        for name in sorted(children + names):
            path = os.path.join(current, name)
            if os.path.islink(path):
                assert not os.path.isdir(path), path
                kind = 'symlink'
            elif os.path.isdir(path):
                kind = 'directory'
            elif os.path.isfile(path):
                kind = 'file'
            else:
                raise ValueError(path)
            entries.append(dict(name=name, kind=kind))
            if kind != 'directory':
                file(path)
        directories[current] = entries
        assert len(directories) <= 512


def origin(name):
    if name in sys.builtin_module_names:
        return dict(kind='builtin')
    if _imp.is_frozen(name):
        return dict(kind='frozen')
    search = sys.path
    prefix = []
    for part in name.split('.'):
        prefix.append(part)
        spec = PathFinder.find_spec('.'.join(prefix), search)
        assert spec and spec.origin and spec.origin not in ('built-in', 'frozen'), name
        search = spec.submodule_search_locations
    path = os.path.realpath(spec.origin)
    file(spec.origin)
    return dict(kind='file', path=path)


def main():
    assert sys.prefix == sys.base_prefix and sys.exec_prefix == sys.base_exec_prefix
    search = list(sys.path)
    assert all(os.path.isabs(p) for p in search)
    absent = []
    for path in search:
        if os.path.isdir(path):
            inventory(path)
        else:
            assert not os.path.lexists(path), path
            absent.append(path)
    executable = os.path.realpath(sys.executable)
    file(executable)
    libdir, library = sysconfig.get_config_var('LIBDIR'), sysconfig.get_config_var('LDLIBRARY')
    if libdir and library and os.path.isfile(os.path.join(libdir, library)):
        file(os.path.join(libdir, library))
    for directory in {os.path.dirname(sys.executable), os.path.dirname(executable)}:
        for path in [os.path.join(directory, 'pyvenv.cfg'),
                     os.path.join(os.path.dirname(directory), 'pyvenv.cfg'),
                     executable + '._pth', os.path.join(directory, 'pybuilddir.txt')]:
            assert not os.path.lexists(path), path
            absent.append(path)
    modules = {name: origin(name) for name in ['os', 'sys', 'pathlib', 'subprocess', 'urllib.parse', 'socket', 'json', 'http.server']}
    result = dict(schema='caushell.python-runtime/v1', version=list(sys.version_info[:3]),
        platform=sys.platform, executable=executable,
        account=dict(uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(), egid=os.getegid()),
        account_home=pwd.getpwuid(os.geteuid()).pw_dir, search_paths=search,
        extension_suffixes=list(EXTENSION_SUFFIXES), site_directories=site.getsitepackages(),
        absent_configuration=sorted(set(absent)), stdlib_names=sorted(sys.stdlib_module_names),
        builtin_modules=sorted(sys.builtin_module_names),
        frozen_modules=sorted(name for name in sys.stdlib_module_names if _imp.is_frozen(name)),
        modules=modules, files=files, directories=directories, symlinks=links)
    json.dump(result, sys.stdout, sort_keys=True, indent=2)
    print()


if __name__ == '__main__':
    main()
