# Archive targets

`option_environment: {name: TAR_OPTIONS, syntax: gnu_tar}` declares native environment options. Observed exported values and command-prefix values enter the effective argv as data. Prefix values take precedence. Environment options are parsed independently before explicit arguments; a missing operand cannot consume an explicit argument. Old option words are normalized before composition. Unknown environment bytes, expansion, ownership or budgets retain an analysis gap.

`archive_extraction: gnu_tar` enables member proofs for `archive_members` write effects. Archive filenames resolve from the invocation directory. Ordered `-C` operands determine the extraction directory without changing shell state or archive lookup.

The initial reader accepts complete uncompressed USTAR/GNU archives containing regular files and directories, with at most 65,536 input bytes, 64 members and 16 archive observations per action. It validates header checksums, sizes, padding boundaries and the complete end marker. Member order and duplicate entries remain in evidence. Member selection, transforms, compressed inputs, extended headers, sparse files, special entries and links remain unproved.

The filesystem content interface supplies the archive bytes and their SHA-256/identity observation. Namespace resolution and same-action write dependencies apply to the source and every output. Absolute/traversing member names, linked or unknown output components, changed observations and exhausted budgets do not produce a complete target set. Evidence contains the source observation, ordered members, output paths and any errors. No archive listing or extraction subprocess is used by the analyzer.
