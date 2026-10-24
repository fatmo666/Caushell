# Python runtime inventory

Capture a trusted Linux CPython 3.11 installation in the execution namespace:

```sh
/usr/bin/python3 -I -S -B tools/python-runtime/capture.py > python-runtime.json
caushell serve-stdio --python-runtime-contract python-runtime.json
```

Keep the inventory under deployment control, outside pending program writes.
Registration is explicit; check requests never refresh it. The collector records
interpreter/standard-library digests, directory entries, symlinks, module origins,
account and search paths. It does not run site startup or import target modules.

The runtime image and native loader remain trusted deployment inputs. During
checks, the filesystem backend must observe the actual execution namespace and
account. The local backend handles absolute interpreter paths; bare names require
a backend providing the execution Shell's lookup, including its command hash.

Inventory bounds are 4,096 files, 512 directories, 128 MiB total file content and
32 MiB per file. Changed or incomplete observations, unsupported startup behavior
and same-action namespace mutations leave the startup boundary unproved.
