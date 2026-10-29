# Pinned Python module CLI binding

This optional executor component binds an existing registered module CLI to its
actual interpreter and installed module. It does not analyze Python source bodies
and does not grant permission by recognizing a module name.

The executor owns the private `serve-host-stdio` pipe and the deployment contract.
The model and tool subprocesses must not inherit that pipe or choose its grants.

1. During controlled image provisioning, run
   `python3 -I -S -B capture.py IMAGE_DIGEST` as the intended execution account.
   Retain and review the manifest; capture alone grants no authority. Pin its hash
   in a separate host policy before evaluating commands.
2. The executor establishes a `NamespaceLease` for the immutable interpreter,
   library/dependency closure and image namespace. The lease callback must verify
   those actual deployment properties. An image label or an untrusted boolean is
   insufficient. Keep the lease through execution completion; without that
   guarantee, retain Ask.
3. Collect the normal execution frame plus `loader.ENVIRONMENT` from the owning
   execution namespace. Use `ModuleContractPlan` with that frame to obtain exact,
   read-only invocation queries without advancing the live session.
4. Supply the executor's decoded interpreter argv, real Shell executable lookup
   (including alias/hash state), account and complete environment to `attest`.
   It checks pinned origins, CPython's own program-name lookup, loader
   environment, shadowing and startup controls. PATH search snapshots include
   entry metadata, so a formerly non-executable candidate cannot silently become
   the selected interpreter. Launcher overrides and invocation-specific venv or
   `._pth` configuration retain Ask.
   Put its identity in `HostCheck.module_identities`.
5. A separate host policy may call `grant_permission` using its preapproved
   manifest hashes. Put this distinct permission in `module_permissions`, and
   bound `HostCheck.lifetime_ms` by the returned remaining lease lifetime.
6. On Allow, use the existing BeginExecution/CompleteExecution handshake. Core
   validates artifacts, namespace and directory snapshots again at BeginExecution.
   Retirement, expiry, restart or a later request needs new evidence and a new
   request-bound permission. Diagnostic evidence in the session store is not a
   capability.

The core only accepts current generic loader facts and explicit CLI permissions.
Registered CLI read/write/network effects continue through ordinary policy. In
particular, cache facts grant no write permission, deletion still asks, incomplete
analysis asks and existing Deny cannot be removed.

This binder currently covers deployment-pinned CPython 3.12 on Linux. Unknown
startup flags/environment, writable/unleased libraries, module or dependency
shadowing, user-site startup, executable `.pth` files and custom site hooks remain
incomplete. `-I -S -B` can establish a smaller loading context; the binder never
rewrites an agent command to add those options. This component is independent of
Pysa/PyFlow and performs no target execution or runtime interception.

`py_compile` writes regular cache files atomically and may create cache directories,
even with `-B`. Its declarative profile bounds default outputs under each input
parent's `__pycache__`, or under a proven `PYTHONPYCACHEPREFIX`. Core checks complete,
bounded, link-free namespace snapshots; symlink escapes, unknown inputs/prefixes,
stdin filename lists and exhausted observation budgets retain Ask.
