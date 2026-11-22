"""Git layout evidence from the owning executor for the frozen RQ2 image."""

import hashlib
import os
from pathlib import Path
import stat


IMAGE = "sha256:510118b7a22eb8f31dbeb57139a70ada52cefa2e374cc660db4be9fc8aa37ef4"
GIT = Path("/usr/bin/git")
GIT_SHA256 = "356db14e102d68a1a37d8a1ac577dfd678d45d46e92f468bef8b7154e7bfdc60"
VARIANT = "git_2_47_3"
SYSTEM_CONFIG = "/etc/gitconfig"


def quiet_namespace(pids):
    live = set()
    exited = 0
    for path in Path("/proc").iterdir():
        if not path.name.isdecimal():
            continue
        try:
            # The comm field can contain spaces and closing parentheses.
            state = (path / "stat").read_text().rsplit(") ", 1)[1].split()[0]
        except FileNotFoundError:
            continue
        # PID 1 can retain exited, orphaned shell children until batch exit.
        if state in {"Z", "X"}:
            exited += 1
        else:
            live.add(int(path.name))
    if live == pids and len({os.readlink(f"/proc/{pid}/ns/mnt") for pid in pids}) == 1:
        return exited
    return None


def executable_digest():
    with GIT.open("rb") as file:
        before = os.fstat(file.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > 8 * 1024 * 1024:
            return None
        digest = hashlib.sha256()
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
        after = os.fstat(file.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_ctime_ns
        ):
            return None
    return digest.hexdigest()


def observe_git_layout(shell, guard, image):
    """Only attest while this worker exclusively owns a paused executor."""
    if image != IMAGE or os.getpid() != 1:
        return None, "unknown_executor_image"
    try:
        if not os.statvfs("/").f_flag & os.ST_RDONLY:
            return None, "writable_root"
        target = shell.boundary()
        pids = {os.getpid(), target.process.pid, guard.pid}
        if len(pids) != 3 or quiet_namespace(pids) is None:
            return None, "unexpected_live_process"
        # These Bash builtins inspect the same shell that owns the pending check.
        probe = target.execute("builtin type -t git; builtin command -v git")
        if probe["returncode"] or probe["output_truncated"] or probe["stdout"].splitlines() != ["file", str(GIT)]:
            return None, "git_resolution_mismatch"
        if executable_digest() != GIT_SHA256:
            return None, "git_digest_mismatch"
        exited = quiet_namespace(pids)
        if exited is None:
            return None, "executor_namespace_changed"
        return {
            "layout": {
                "variant": VARIANT,
                "system_config": SYSTEM_CONFIG,
                "configuration_snapshot_held": True,
            },
            "executable": str(GIT),
            "sha256": GIT_SHA256,
            "image": IMAGE,
            "quiescent_pids": sorted(pids),
            "exited_processes": exited,
        }, "held"
    except (OSError, ValueError, IndexError):
        return None, "observation_unavailable"
