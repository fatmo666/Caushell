"""Static loader binding for a deployment-pinned CPython CLI.

This trusted executor component never imports the proposed module or compiles,
parses, executes, or inspects the body of a user source file. The owner must
maintain the pinned image/immutable library closure for the admission lifetime.
It returns identity facts only; permission is a separate explicit host policy.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import time


class IncompleteIdentity(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def metadata(value):
    return dict(device=value.st_dev, inode=value.st_ino, size=value.st_size,
                modified_seconds=value.st_mtime_ns // 10**9,
                modified_nanos=value.st_mtime_ns % 10**9,
                changed_seconds=value.st_ctime_ns // 10**9,
                changed_nanos=value.st_ctime_ns % 10**9)


def metadata_bytes(value):
    return struct.pack("<QQQqqqq", value["device"], value["inode"], value["size"],
                       value["modified_seconds"], value["modified_nanos"],
                       value["changed_seconds"], value["changed_nanos"])


def entry(path):
    try:
        value = os.lstat(path)
    except FileNotFoundError:
        return dict(kind="missing")
    if stat.S_ISLNK(value.st_mode):
        return dict(kind="symlink", target=os.readlink(path))
    if stat.S_ISDIR(value.st_mode):
        return dict(kind="directory")
    return dict(kind="file")


def file_digest(path):
    path = Path(path)
    if str(path.resolve(strict=True)) != str(path) or not path.is_file():
        raise IncompleteIdentity("runtime artifacts must use resolved regular paths")
    before = path.stat()
    if before.st_size > 33554432:
        raise IncompleteIdentity("runtime artifact byte budget exceeded")
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    if metadata(before) != metadata(path.stat()):
        raise IncompleteIdentity("runtime artifact changed")
    return dict(sha256=h.hexdigest(), size=before.st_size)


def directory_observation(path):
    path = str(path)
    if str(Path(path).resolve(strict=True)) != path:
        raise IncompleteIdentity("search roots must be namespace-resolved")
    before = os.stat(path)
    entries = []
    for name in sorted(os.listdir(path), key=os.fsencode):
        if not name or name in (".", "..") or "/" in name or "\0" in name:
            raise IncompleteIdentity("invalid search directory entry")
        value = os.lstat(os.path.join(path, name))
        kind = (0 if stat.S_ISREG(value.st_mode) else 1 if stat.S_ISDIR(value.st_mode)
                else 2 if stat.S_ISLNK(value.st_mode) else 3)
        entries.append((name, kind, metadata(value)))
    names = sum(len(os.fsencode(name)) for name, _, _ in entries)
    if len(entries) > 4096 or names > 65536 or metadata(before) != metadata(os.stat(path)):
        raise IncompleteIdentity("search directory is changed or exceeds its budget")
    h = hashlib.sha256(metadata_bytes(metadata(before)))
    for name, kind, identity in entries:
        encoded = name.encode("utf-8", "strict")
        h.update(struct.pack("<Q", len(encoded)))
        h.update(encoded)
        h.update(bytes([kind]))
        h.update(metadata_bytes(identity))
    return dict(source="current_process", path=path, status="complete",
                limits=dict(max_entries=4096, max_name_bytes=65536),
                entries_observed=len(entries), name_bytes_observed=names,
                sha256=h.hexdigest(), identity=metadata(before), detail=None), entries


@dataclass(frozen=True)
class NamespaceLease:
    """Issued by the deployment owner, kept current through execution completion.

    is_current must verify the immutable image/library roots and the actual
    execution namespace, not merely echo fields supplied by a tool.
    """
    namespace_id: str
    image_digest: str
    deadline: float
    is_current: object

    def remaining_ms(self):
        remaining = int((self.deadline - time.monotonic()) * 1000)
        if remaining <= 0 or not self.is_current(self.namespace_id, self.image_digest):
            raise IncompleteIdentity("deployment namespace lease is stale")
        return min(remaining, 3600000)


# Values affect startup/search, not the source being compiled. Unknown values
# remain incomplete even if shell-variable discovery otherwise claims complete.
ENVIRONMENT = ("PATH", "HOME", "__PYVENV_LAUNCHER__", "PYTHONEXECUTABLE", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_ORIGIN_PATH",
               "LD_ASSUME_KERNEL", "LD_PROFILE", "LD_PROFILE_OUTPUT", "LD_DEBUG",
               "LD_DEBUG_OUTPUT", "GCONV_PATH", "LOCPATH", "PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE", "PYTHONSTARTUP",
               "PYTHONINSPECT", "PYTHONWARNINGS", "PYTHONSAFEPATH",
               "PYTHONNOUSERSITE", "PYTHONPYCACHEPREFIX", "PYTHONOPTIMIZE",
               "PYTHONDONTWRITEBYTECODE", "PYTHONDEVMODE", "PYTHONUTF8")


def interpreter_lookup(argv0, cwd, environment, executable):
    """Bind CPython's own program-name lookup as well as the Shell's lookup.

    Shell aliases/hash entries may select an executable different from the
    first same-named executable on PATH. CPython performs its own PATH search.
    Original symlink spellings also participate in venv/._pth discovery.
    """
    namespace = []
    directories = {}

    def observe(path):
        path = os.path.abspath(path)
        for ancestor in reversed(Path(path).parents):
            name = str(ancestor)
            namespace.append(dict(source="current_process", path=name, entry=entry(name)))
        namespace.append(dict(source="current_process", path=path, entry=entry(path)))
        return path

    if not argv0 or "\0" in argv0:
        raise IncompleteIdentity("interpreter program name is unknown")
    if "/" in argv0:
        spelling = observe(argv0 if os.path.isabs(argv0) else os.path.join(cwd, argv0))
    else:
        path = environment["PATH"]
        if path["status"] != "present":
            raise IncompleteIdentity("CPython program-name PATH lookup is unproven")
        spelling = None
        for directory in path["value"].split(os.pathsep):
            directory = directory if os.path.isabs(directory) else os.path.join(cwd, directory)
            if os.path.isdir(directory):
                resolved_directory = str(Path(directory).resolve(strict=True))
                directories[resolved_directory] = directory_observation(resolved_directory)[0]
            candidate = observe(os.path.join(directory, argv0))
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                spelling = candidate
                break
        if spelling is None:
            raise IncompleteIdentity("CPython program name cannot be located")
    if os.path.realpath(spelling) != executable:
        raise IncompleteIdentity("Shell and CPython executable lookup disagree")
    directory = os.path.dirname(spelling)
    for configuration in (spelling + "._pth", directory + "/pyvenv.cfg",
                          os.path.dirname(directory) + "/pyvenv.cfg"):
        configuration = observe(configuration)
        if entry(configuration) != dict(kind="missing"):
            raise IncompleteIdentity("invocation-specific runtime path configuration is present")
    # Include link targets/ancestors too; immutable artifact files alone do not
    # pin a mutable symlink spelling. Path.resolve rejects missing loops.
    for observation in list(namespace):
        if observation["entry"].get("kind") == "symlink":
            resolved = str(Path(observation["path"]).resolve(strict=True))
            observe(resolved)
    return namespace, list(directories.values())


def attest(query, manifest, execution, lease):
    """Bind an exact Caushell ModuleContractPlan query to pinned loader facts.

    manifest and lease are trusted deployment inputs. execution comes from the
    owning executor's current decoded invocation and shell executable lookup,
    including aliases/hash state; this component never guesses lookup from PATH.
    """
    if (manifest.get("schema") != "caushell.cpython-module-cli/v1"
            or manifest.get("platform") != "linux"
            or manifest.get("version", [])[:2] != [3, 12]
            or lease.image_digest != manifest.get("image_digest")):
        raise IncompleteIdentity("unsupported or unpinned deployment contract")
    lifetime = lease.remaining_ms()
    if (execution["namespace_id"] != lease.namespace_id
            or execution["node_id"] != query["node_id"]
            or execution["binding"] != query["binding"]
            or execution["cwd"] != query["cwd"]
            or execution["executable"] != manifest["executable"]
            or execution.get("account") != manifest["account"]
            or query["runtime"] != "python"):
        raise IncompleteIdentity("interpreter lookup or invocation context differs")
    argv = execution["argv"]
    try:
        index = argv.index("-m", 1)
    except ValueError as error:
        raise IncompleteIdentity("not a decoded module entry") from error
    options = argv[1:index]
    if any(option not in ("-I", "-S", "-E", "-s", "-P", "-B", "-q", "-u", "-O", "-OO") for option in options):
        raise IncompleteIdentity("unmodeled interpreter startup option")
    if index + 1 >= len(argv) or argv[index + 1] != query["module"]:
        raise IncompleteIdentity("module binding differs")
    module = query["module"]
    if module not in manifest["module_origins"]:
        raise IncompleteIdentity("module has no pinned CLI origin")
    environment = execution["environment"]
    if not execution.get("environment_complete"):
        raise IncompleteIdentity("executor environment capture is incomplete")
    for name, value in environment.items():
        if (name.startswith("LD_") or name in ("GCONV_PATH", "LOCPATH")) and value.get("status") == "present" and value.get("value"):
            raise IncompleteIdentity("dynamic-loader environment is not pinned")
        if name.startswith("PYTHON") and name != "PYTHONPYCACHEPREFIX" and "-I" not in options and "-E" not in options and value.get("status") == "present" and value.get("value"):
            raise IncompleteIdentity("unmodeled Python environment control")
    if any(environment.get(name, {}).get("status") not in ("absent", "present") for name in ENVIRONMENT):
        raise IncompleteIdentity("loader environment is unknown")
    if any(environment[name]["status"] == "present" and environment[name].get("value")
           for name in ("__PYVENV_LAUNCHER__", "PYTHONEXECUTABLE")):
        raise IncompleteIdentity("interpreter launcher environment is not pinned")
    namespace, directories = interpreter_lookup(argv[0], query["cwd"], environment, manifest["executable"])
    roots = list(manifest["search_roots"])
    if "-S" not in options:
        roots += list(manifest["site_directories"])
        home_setting = environment["HOME"]
        home = home_setting.get("value") if home_setting["status"] == "present" else manifest["account_home"]
        if not home or not home.startswith("/"):
            raise IncompleteIdentity("account home is unknown")
        user_site = home.rstrip("/") + "/.local/lib/python3.12/site-packages"
        if "-I" not in options and "-s" not in options:
            observed = entry(user_site)
            if observed != dict(kind="missing"):
                raise IncompleteIdentity("user-site startup is not absent")
            namespace.append(dict(source="current_process", path=user_site, entry=observed))
    cwd_search = "-I" not in options and "-P" not in options
    if cwd_search:
        roots.insert(0, query["cwd"])
    for path in dict.fromkeys(roots):
        observed = entry(path)
        namespace.append(dict(source="current_process", path=path, entry=observed))
        if observed == dict(kind="missing"):
            continue
        snapshot, entries = directory_observation(path)
        directories.append(snapshot)
        if len(directories) > 64:
            raise IncompleteIdentity("search path budget exceeded")
        if path == query["cwd"] and cwd_search:
            reserved = set(manifest["reserved_import_names"]) | {module.split(".")[0], "sitecustomize", "usercustomize"}
            suffixes = (".py", ".pyc", *manifest["extension_suffixes"])
            if any(name in reserved or any(name == base + suffix for suffix in suffixes for base in reserved)
                   for name, _, _ in entries):
                raise IncompleteIdentity("workspace can shadow the registered loading closure")
        if "-S" not in options:
            if path in manifest["site_directories"] and any(name.endswith(".pth") for name, _, _ in entries):
                raise IncompleteIdentity("executable .pth startup needs a separate loading contract")
            for name in ("sitecustomize", "usercustomize"):
                if any(n == name or n == name + ".py" or n == name + ".pyc" or any(n == name + s for s in manifest["extension_suffixes"])
                       for n, _, _ in entries):
                    raise IncompleteIdentity("custom site startup is not covered")
    for path in manifest["absent_configuration"]:
        observed = entry(path)
        if observed != dict(kind="missing"):
            raise IncompleteIdentity("runtime path configuration changed")
        namespace.append(dict(source="current_process", path=path, entry=observed))
    files = manifest["files"]
    origin = manifest["module_origins"][module]
    if manifest["executable"] not in files or origin not in files or len(files) > 128:
        raise IncompleteIdentity("runtime file closure is incomplete")
    for path, expected in files.items():
        if file_digest(path) != expected:
            raise IncompleteIdentity("pinned runtime or module digest changed")
    identity = dict(invocation=query, namespace_id=lease.namespace_id,
                    loading_contract_sha256=digest(manifest), executable=manifest["executable"],
                    module_file=origin, files=files, namespace=namespace,
                    directories=directories, environment=dict(environment))
    for snapshot in directories:
        if directory_observation(snapshot["path"])[0] != snapshot:
            raise IncompleteIdentity("search namespace changed during attestation")
    return identity, min(lifetime, lease.remaining_ms())


def grant_permission(identity, grant_id, approved_contract_hashes):
    """A separate, explicit host policy input; identity never implies permission."""
    if identity["loading_contract_sha256"] not in approved_contract_hashes:
        raise IncompleteIdentity("host policy has not authorized this loading contract")
    return dict(grant_id=grant_id, namespace_id=identity["namespace_id"],
                identity_sha256=digest(identity), loading_contract_sha256=identity["loading_contract_sha256"])
