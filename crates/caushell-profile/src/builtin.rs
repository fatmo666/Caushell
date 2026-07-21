use crate::{LoadProfileError, ProfileRegistry, RegistryError, load_command_profile_from_str};

struct BuiltInProfileSource {
    profile_id: &'static str,
    content: &'static str,
}

const BUILT_IN_PROFILE_SOURCES: &[BuiltInProfileSource] = &[
    BuiltInProfileSource {
        profile_id: "alias",
        content: include_str!("../profiles/alias.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "awk",
        content: include_str!("../profiles/awk.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "bash",
        content: include_str!("../profiles/bash.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "busybox",
        content: include_str!("../profiles/busybox.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "cargo",
        content: include_str!("../profiles/cargo.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "base64",
        content: include_str!("../profiles/base64.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "blkdiscard",
        content: include_str!("../profiles/blkdiscard.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "bg",
        content: include_str!("../profiles/bg.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "cat",
        content: include_str!("../profiles/cat.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "cd",
        content: include_str!("../profiles/cd.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "chgrp",
        content: include_str!("../profiles/chgrp.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "chmod",
        content: include_str!("../profiles/chmod.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "chown",
        content: include_str!("../profiles/chown.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "chrt",
        content: include_str!("../profiles/chrt.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "cfdisk",
        content: include_str!("../profiles/cfdisk.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "code",
        content: include_str!("../profiles/code.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "command",
        content: include_str!("../profiles/command.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "cp",
        content: include_str!("../profiles/cp.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "crontab",
        content: include_str!("../profiles/crontab.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "csplit",
        content: include_str!("../profiles/csplit.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dd",
        content: include_str!("../profiles/dd.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "df",
        content: include_str!("../profiles/df.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "diff",
        content: include_str!("../profiles/diff.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "doas",
        content: include_str!("../profiles/doas.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "fdisk",
        content: include_str!("../profiles/fdisk.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "conan",
        content: include_str!("../profiles/conan.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "curl",
        content: include_str!("../profiles/curl.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "cut",
        content: include_str!("../profiles/cut.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "apt-get",
        content: include_str!("../profiles/apt-get.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "env",
        content: include_str!("../profiles/env.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "exec",
        content: include_str!("../profiles/exec.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "eval",
        content: include_str!("../profiles/eval.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "fakeroot",
        content: include_str!("../profiles/fakeroot.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ed",
        content: include_str!("../profiles/ed.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "echo",
        content: include_str!("../profiles/echo.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "fg",
        content: include_str!("../profiles/fg.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "find",
        content: include_str!("../profiles/find.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "file",
        content: include_str!("../profiles/file.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "firejail",
        content: include_str!("../profiles/firejail.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "flock",
        content: include_str!("../profiles/flock.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "git",
        content: include_str!("../profiles/git.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "gdisk",
        content: include_str!("../profiles/gdisk.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "gcc",
        content: include_str!("../profiles/gcc.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "gunzip",
        content: include_str!("../profiles/gunzip.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "grep",
        content: include_str!("../profiles/grep.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "gzip",
        content: include_str!("../profiles/gzip.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "iconv",
        content: include_str!("../profiles/iconv.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "head",
        content: include_str!("../profiles/head.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "install",
        content: include_str!("../profiles/install.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ionice",
        content: include_str!("../profiles/ionice.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "jq",
        content: include_str!("../profiles/jq.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "kill",
        content: include_str!("../profiles/kill.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "killall",
        content: include_str!("../profiles/killall.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "make",
        content: include_str!("../profiles/make.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ln",
        content: include_str!("../profiles/ln.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "less",
        content: include_str!("../profiles/less.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ls",
        content: include_str!("../profiles/ls.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mkdir",
        content: include_str!("../profiles/mkdir.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mktemp",
        content: include_str!("../profiles/mktemp.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mkfs",
        content: include_str!("../profiles/mkfs.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mkfs.bfs",
        content: include_str!("../profiles/mkfs.bfs.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mkfs.cramfs",
        content: include_str!("../profiles/mkfs.cramfs.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mkfs.minix",
        content: include_str!("../profiles/mkfs.minix.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mke2fs",
        content: include_str!("../profiles/mke2fs.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "more",
        content: include_str!("../profiles/more.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mkswap",
        content: include_str!("../profiles/mkswap.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mv",
        content: include_str!("../profiles/mv.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mypy",
        content: include_str!("../profiles/mypy.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "nc",
        content: include_str!("../profiles/nc.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "nice",
        content: include_str!("../profiles/nice.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "nl",
        content: include_str!("../profiles/nl.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "nohup",
        content: include_str!("../profiles/nohup.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "npm",
        content: include_str!("../profiles/npm.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "nsenter",
        content: include_str!("../profiles/nsenter.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "npx",
        content: include_str!("../profiles/npx.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "openssl",
        content: include_str!("../profiles/openssl.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "node",
        content: include_str!("../profiles/node.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "od",
        content: include_str!("../profiles/od.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "xxd",
        content: include_str!("../profiles/xxd.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "perl",
        content: include_str!("../profiles/perl.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "perf",
        content: include_str!("../profiles/perf.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "parted",
        content: include_str!("../profiles/parted.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pgrep",
        content: include_str!("../profiles/pgrep.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pkill",
        content: include_str!("../profiles/pkill.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pip",
        content: include_str!("../profiles/pip.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "printf",
        content: include_str!("../profiles/printf.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ps",
        content: include_str!("../profiles/ps.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "psql",
        content: include_str!("../profiles/psql.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "python",
        content: include_str!("../profiles/python.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pwd",
        content: include_str!("../profiles/pwd.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "read",
        content: include_str!("../profiles/read.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rm",
        content: include_str!("../profiles/rm.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rmdir",
        content: include_str!("../profiles/rmdir.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rlwrap",
        content: include_str!("../profiles/rlwrap.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rsync",
        content: include_str!("../profiles/rsync.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "runuser",
        content: include_str!("../profiles/runuser.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "scp",
        content: include_str!("../profiles/scp.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "script",
        content: include_str!("../profiles/script.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "shred",
        content: include_str!("../profiles/shred.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "shuf",
        content: include_str!("../profiles/shuf.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sleep",
        content: include_str!("../profiles/sleep.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sfdisk",
        content: include_str!("../profiles/sfdisk.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sgdisk",
        content: include_str!("../profiles/sgdisk.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sed",
        content: include_str!("../profiles/sed.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "setsid",
        content: include_str!("../profiles/setsid.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sh",
        content: include_str!("../profiles/sh.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ssh",
        content: include_str!("../profiles/ssh.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ssh-keygen",
        content: include_str!("../profiles/ssh-keygen.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "strings",
        content: include_str!("../profiles/strings.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "strace",
        content: include_str!("../profiles/strace.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sudo",
        content: include_str!("../profiles/sudo.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "stdbuf",
        content: include_str!("../profiles/stdbuf.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "source",
        content: include_str!("../profiles/source.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sort",
        content: include_str!("../profiles/sort.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "split",
        content: include_str!("../profiles/split.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "systemd-run",
        content: include_str!("../profiles/systemd-run.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tar",
        content: include_str!("../profiles/tar.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "taskset",
        content: include_str!("../profiles/taskset.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tail",
        content: include_str!("../profiles/tail.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tee",
        content: include_str!("../profiles/tee.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "time",
        content: include_str!("../profiles/time.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "timeout",
        content: include_str!("../profiles/timeout.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "touch",
        content: include_str!("../profiles/touch.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "truncate",
        content: include_str!("../profiles/truncate.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "top",
        content: include_str!("../profiles/top.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tr",
        content: include_str!("../profiles/tr.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tree",
        content: include_str!("../profiles/tree.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "unshare",
        content: include_str!("../profiles/unshare.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "true",
        content: include_str!("../profiles/true.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "valgrind",
        content: include_str!("../profiles/valgrind.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "unalias",
        content: include_str!("../profiles/unalias.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "uniq",
        content: include_str!("../profiles/uniq.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "unzip",
        content: include_str!("../profiles/unzip.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "vim",
        content: include_str!("../profiles/vim.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "wget",
        content: include_str!("../profiles/wget.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "wc",
        content: include_str!("../profiles/wc.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "which",
        content: include_str!("../profiles/which.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "whoami",
        content: include_str!("../profiles/whoami.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "wipefs",
        content: include_str!("../profiles/wipefs.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "xargs",
        content: include_str!("../profiles/xargs.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "xvfb-run",
        content: include_str!("../profiles/xvfb-run.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "yarn",
        content: include_str!("../profiles/yarn.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "zcat",
        content: include_str!("../profiles/zcat.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "zsh",
        content: include_str!("../profiles/zsh.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "cmake",
        content: include_str!("../profiles/cmake.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "deep",
        content: include_str!("../profiles/deep.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dotenv",
        content: include_str!("../profiles/dotenv.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dpkg-query",
        content: include_str!("../profiles/dpkg-query.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dvc",
        content: include_str!("../profiles/dvc.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "flake8",
        content: include_str!("../profiles/flake8.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "glom",
        content: include_str!("../profiles/glom.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "gtts-cli",
        content: include_str!("../profiles/gtts-cli.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "hexdump",
        content: include_str!("../profiles/hexdump.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "meson",
        content: include_str!("../profiles/meson.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mkdocs",
        content: include_str!("../profiles/mkdocs.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "nikola",
        content: include_str!("../profiles/nikola.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pipdeptree",
        content: include_str!("../profiles/pipdeptree.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pkg-config",
        content: include_str!("../profiles/pkg-config.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pygmentize",
        content: include_str!("../profiles/pygmentize.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pyright",
        content: include_str!("../profiles/pyright.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pyreverse",
        content: include_str!("../profiles/pyreverse.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "qr",
        content: include_str!("../profiles/qr.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rg",
        content: include_str!("../profiles/rg.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "safety",
        content: include_str!("../profiles/safety.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "scrapy",
        content: include_str!("../profiles/scrapy.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sqlfluff",
        content: include_str!("../profiles/sqlfluff.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tldextract",
        content: include_str!("../profiles/tldextract.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "yamllint",
        content: include_str!("../profiles/yamllint.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "basename",
        content: include_str!("../profiles/basename.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "bind",
        content: include_str!("../profiles/bind.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "bzip2",
        content: include_str!("../profiles/bzip2.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "cal",
        content: include_str!("../profiles/cal.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "column",
        content: include_str!("../profiles/column.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "comm",
        content: include_str!("../profiles/comm.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "compress",
        content: include_str!("../profiles/compress.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "cpio",
        content: include_str!("../profiles/cpio.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "date",
        content: include_str!("../profiles/date.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dig",
        content: include_str!("../profiles/dig.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dirname",
        content: include_str!("../profiles/dirname.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "du",
        content: include_str!("../profiles/du.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "false",
        content: include_str!("../profiles/false.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "finger",
        content: include_str!("../profiles/finger.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "fold",
        content: include_str!("../profiles/fold.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "groups",
        content: include_str!("../profiles/groups.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "history",
        content: include_str!("../profiles/history.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "hostname",
        content: include_str!("../profiles/hostname.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ifconfig",
        content: include_str!("../profiles/ifconfig.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "jobs",
        content: include_str!("../profiles/jobs.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "join",
        content: include_str!("../profiles/join.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "man",
        content: include_str!("../profiles/man.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "md5sum",
        content: include_str!("../profiles/md5sum.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mount",
        content: include_str!("../profiles/mount.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "paste",
        content: include_str!("../profiles/paste.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ping",
        content: include_str!("../profiles/ping.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pstree",
        content: include_str!("../profiles/pstree.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pushd",
        content: include_str!("../profiles/pushd.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "readlink",
        content: include_str!("../profiles/readlink.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rename",
        content: include_str!("../profiles/rename.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rev",
        content: include_str!("../profiles/rev.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "seq",
        content: include_str!("../profiles/seq.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "set",
        content: include_str!("../profiles/set.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "shopt",
        content: include_str!("../profiles/shopt.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tac",
        content: include_str!("../profiles/tac.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "uname",
        content: include_str!("../profiles/uname.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "w",
        content: include_str!("../profiles/w.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "watch",
        content: include_str!("../profiles/watch.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "who",
        content: include_str!("../profiles/who.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "yes",
        content: include_str!("../profiles/yes.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "aider-chat",
        content: include_str!("../profiles/aider-chat.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "base32",
        content: include_str!("../profiles/base32.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "chcp",
        content: include_str!("../profiles/chcp.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "cmp",
        content: include_str!("../profiles/cmp.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "docker",
        content: include_str!("../profiles/docker.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "drizzle-kit",
        content: include_str!("../profiles/drizzle-kit.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "expand",
        content: include_str!("../profiles/expand.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "fmt",
        content: include_str!("../profiles/fmt.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "gh",
        content: include_str!("../profiles/gh.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ghcs",
        content: include_str!("../profiles/ghcs.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "nano",
        content: include_str!("../profiles/nano.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pr",
        content: include_str!("../profiles/pr.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "prisma",
        content: include_str!("../profiles/prisma.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ptx",
        content: include_str!("../profiles/ptx.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "test",
        content: include_str!("../profiles/test.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "unexpand",
        content: include_str!("../profiles/unexpand.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "apropos",
        content: include_str!("../profiles/apropos.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "arch",
        content: include_str!("../profiles/arch.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "b2sum",
        content: include_str!("../profiles/b2sum.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "bunzip2",
        content: include_str!("../profiles/bunzip2.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "chcon",
        content: include_str!("../profiles/chcon.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "cksum",
        content: include_str!("../profiles/cksum.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "clear",
        content: include_str!("../profiles/clear.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dir",
        content: include_str!("../profiles/dir.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dircolors",
        content: include_str!("../profiles/dircolors.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "expr",
        content: include_str!("../profiles/expr.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "factor",
        content: include_str!("../profiles/factor.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "hostid",
        content: include_str!("../profiles/hostid.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "id",
        content: include_str!("../profiles/id.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "info",
        content: include_str!("../profiles/info.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "link",
        content: include_str!("../profiles/link.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "logname",
        content: include_str!("../profiles/logname.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "md5",
        content: include_str!("../profiles/md5.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mkfifo",
        content: include_str!("../profiles/mkfifo.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mknod",
        content: include_str!("../profiles/mknod.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "nproc",
        content: include_str!("../profiles/nproc.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "numfmt",
        content: include_str!("../profiles/numfmt.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pathchk",
        content: include_str!("../profiles/pathchk.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pinky",
        content: include_str!("../profiles/pinky.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "popd",
        content: include_str!("../profiles/popd.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "printenv",
        content: include_str!("../profiles/printenv.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "realpath",
        content: include_str!("../profiles/realpath.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "runcon",
        content: include_str!("../profiles/runcon.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sha1sum",
        content: include_str!("../profiles/sha1sum.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sha224sum",
        content: include_str!("../profiles/sha224sum.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sha256sum",
        content: include_str!("../profiles/sha256sum.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sha384sum",
        content: include_str!("../profiles/sha384sum.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sha512sum",
        content: include_str!("../profiles/sha512sum.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "stat",
        content: include_str!("../profiles/stat.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "stty",
        content: include_str!("../profiles/stty.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "su",
        content: include_str!("../profiles/su.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sum",
        content: include_str!("../profiles/sum.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sync",
        content: include_str!("../profiles/sync.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tmux",
        content: include_str!("../profiles/tmux.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tsort",
        content: include_str!("../profiles/tsort.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tty",
        content: include_str!("../profiles/tty.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "unlink",
        content: include_str!("../profiles/unlink.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "users",
        content: include_str!("../profiles/users.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "vdir",
        content: include_str!("../profiles/vdir.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "zless",
        content: include_str!("../profiles/zless.yaml"),
    },
];

#[derive(Debug)]
pub enum BuiltInRegistryError {
    LoadProfile {
        profile_id: &'static str,
        source: LoadProfileError,
    },
    Registry(RegistryError),
}

impl std::fmt::Display for BuiltInRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LoadProfile { profile_id, source } => {
                write!(
                    f,
                    "failed to load built-in profile {profile_id:?}: {source}"
                )
            }
            Self::Registry(source) => write!(f, "failed to build built-in registry: {source}"),
        }
    }
}

impl std::error::Error for BuiltInRegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LoadProfile { source, .. } => Some(source),
            Self::Registry(source) => Some(source),
        }
    }
}

pub(crate) fn load_built_in_registry() -> Result<ProfileRegistry, BuiltInRegistryError> {
    let mut profiles = Vec::with_capacity(BUILT_IN_PROFILE_SOURCES.len());

    for source in BUILT_IN_PROFILE_SOURCES {
        let profile = load_command_profile_from_str(source.content).map_err(|error| {
            BuiltInRegistryError::LoadProfile {
                profile_id: source.profile_id,
                source: error,
            }
        })?;
        profiles.push(profile);
    }

    ProfileRegistry::from_profiles(profiles).map_err(BuiltInRegistryError::Registry)
}

#[cfg(test)]
mod tests {
    use super::{BUILT_IN_PROFILE_SOURCES, load_built_in_registry};
    use crate::CommandProfile;

    #[test]
    fn built_in_registry_loads_compiled_profiles() {
        let registry = load_built_in_registry().expect("expected built-in registry to load");

        assert_eq!(registry.len(), BUILT_IN_PROFILE_SOURCES.len());
        assert_eq!(
            registry
                .lookup("alias")
                .profile
                .map(CommandProfile::primary_name),
            Some("alias")
        );
        assert_eq!(
            registry
                .lookup("bash")
                .profile
                .map(CommandProfile::primary_name),
            Some("bash")
        );
        assert_eq!(
            registry
                .lookup("git")
                .profile
                .map(CommandProfile::primary_name),
            Some("git")
        );
        assert_eq!(
            registry
                .lookup("echo")
                .profile
                .map(CommandProfile::primary_name),
            Some("echo")
        );
        assert_eq!(
            registry
                .lookup("ls")
                .profile
                .map(CommandProfile::primary_name),
            Some("ls")
        );
        assert_eq!(
            registry
                .lookup("nl")
                .profile
                .map(CommandProfile::primary_name),
            Some("nl")
        );
        assert_eq!(
            registry
                .lookup("tail")
                .profile
                .map(CommandProfile::primary_name),
            Some("tail")
        );
        assert_eq!(
            registry
                .lookup("pwd")
                .profile
                .map(CommandProfile::primary_name),
            Some("pwd")
        );
        assert_eq!(
            registry
                .lookup("sort")
                .profile
                .map(CommandProfile::primary_name),
            Some("sort")
        );
        assert_eq!(
            registry
                .lookup("gzip")
                .profile
                .map(CommandProfile::primary_name),
            Some("gzip")
        );
        assert_eq!(
            registry
                .lookup("gunzip")
                .profile
                .map(CommandProfile::primary_name),
            Some("gunzip")
        );
        assert_eq!(
            registry
                .lookup("base64")
                .profile
                .map(CommandProfile::primary_name),
            Some("base64")
        );
        assert_eq!(
            registry
                .lookup("iconv")
                .profile
                .map(CommandProfile::primary_name),
            Some("iconv")
        );
        assert_eq!(
            registry
                .lookup("jq")
                .profile
                .map(CommandProfile::primary_name),
            Some("jq")
        );
        assert_eq!(
            registry
                .lookup("kill")
                .profile
                .map(CommandProfile::primary_name),
            Some("kill")
        );
        assert_eq!(
            registry
                .lookup("pkill")
                .profile
                .map(CommandProfile::primary_name),
            Some("pkill")
        );
        assert_eq!(
            registry
                .lookup("killall")
                .profile
                .map(CommandProfile::primary_name),
            Some("killall")
        );
        assert_eq!(
            registry
                .lookup("fg")
                .profile
                .map(CommandProfile::primary_name),
            Some("fg")
        );
        assert_eq!(
            registry
                .lookup("bg")
                .profile
                .map(CommandProfile::primary_name),
            Some("bg")
        );
        assert_eq!(
            registry
                .lookup("cargo")
                .profile
                .map(CommandProfile::primary_name),
            Some("cargo")
        );
        assert_eq!(
            registry
                .lookup("make")
                .profile
                .map(CommandProfile::primary_name),
            Some("make")
        );
        assert_eq!(
            registry
                .lookup("npm")
                .profile
                .map(CommandProfile::primary_name),
            Some("npm")
        );
        assert_eq!(
            registry
                .lookup("npx")
                .profile
                .map(CommandProfile::primary_name),
            Some("npx")
        );
        assert_eq!(
            registry
                .lookup("mkfs.ext4")
                .profile
                .map(CommandProfile::primary_name),
            Some("mke2fs")
        );
        assert_eq!(
            registry
                .lookup("mkfs.xfs")
                .profile
                .map(CommandProfile::primary_name),
            Some("mkfs")
        );
        assert_eq!(
            registry
                .lookup("mkfs.bfs")
                .profile
                .map(CommandProfile::primary_name),
            Some("mkfs.bfs")
        );
        assert_eq!(
            registry
                .lookup("mkfs.cramfs")
                .profile
                .map(CommandProfile::primary_name),
            Some("mkfs.cramfs")
        );
        assert_eq!(
            registry
                .lookup("mkfs.minix")
                .profile
                .map(CommandProfile::primary_name),
            Some("mkfs.minix")
        );
        assert_eq!(
            registry
                .lookup("openssl")
                .profile
                .map(CommandProfile::primary_name),
            Some("openssl")
        );
        assert_eq!(
            registry
                .lookup("gzcat")
                .profile
                .map(CommandProfile::primary_name),
            Some("zcat")
        );
        assert_eq!(
            registry
                .lookup("gawk")
                .profile
                .map(CommandProfile::primary_name),
            Some("awk")
        );
        assert_eq!(
            registry
                .lookup("cp")
                .profile
                .map(CommandProfile::primary_name),
            Some("cp")
        );
        assert_eq!(
            registry
                .lookup("cfdisk")
                .profile
                .map(CommandProfile::primary_name),
            Some("cfdisk")
        );
        assert_eq!(
            registry
                .lookup("dd")
                .profile
                .map(CommandProfile::primary_name),
            Some("dd")
        );
        assert_eq!(
            registry
                .lookup("chmod")
                .profile
                .map(CommandProfile::primary_name),
            Some("chmod")
        );
        assert_eq!(
            registry
                .lookup("chown")
                .profile
                .map(CommandProfile::primary_name),
            Some("chown")
        );
        assert_eq!(
            registry
                .lookup("chgrp")
                .profile
                .map(CommandProfile::primary_name),
            Some("chgrp")
        );
        assert_eq!(
            registry
                .lookup("curl")
                .profile
                .map(CommandProfile::primary_name),
            Some("curl")
        );
        assert_eq!(
            registry
                .lookup("env")
                .profile
                .map(CommandProfile::primary_name),
            Some("env")
        );
        assert_eq!(
            registry
                .lookup("find")
                .profile
                .map(CommandProfile::primary_name),
            Some("find")
        );
        assert_eq!(
            registry
                .lookup("gdisk")
                .profile
                .map(CommandProfile::primary_name),
            Some("gdisk")
        );
        assert_eq!(
            registry
                .lookup("head")
                .profile
                .map(CommandProfile::primary_name),
            Some("head")
        );
        assert_eq!(
            registry
                .lookup("nodejs")
                .profile
                .map(CommandProfile::primary_name),
            Some("node")
        );
        assert_eq!(
            registry
                .lookup("perl")
                .profile
                .map(CommandProfile::primary_name),
            Some("perl")
        );
        assert_eq!(
            registry
                .lookup("scp")
                .profile
                .map(CommandProfile::primary_name),
            Some("scp")
        );
        assert_eq!(
            registry
                .lookup("sgdisk")
                .profile
                .map(CommandProfile::primary_name),
            Some("sgdisk")
        );
        assert_eq!(
            registry
                .lookup("python3")
                .profile
                .map(CommandProfile::primary_name),
            Some("python")
        );
        assert_eq!(
            registry
                .lookup("python3.12")
                .profile
                .map(CommandProfile::primary_name),
            Some("python")
        );
        assert_eq!(
            registry
                .lookup("rsync")
                .profile
                .map(CommandProfile::primary_name),
            Some("rsync")
        );
        assert_eq!(
            registry
                .lookup("egrep")
                .profile
                .map(CommandProfile::primary_name),
            Some("grep")
        );
        assert_eq!(
            registry
                .lookup("fgrep")
                .profile
                .map(CommandProfile::primary_name),
            Some("grep")
        );
        assert_eq!(
            registry
                .lookup("sh")
                .profile
                .map(CommandProfile::primary_name),
            Some("sh")
        );
        assert_eq!(
            registry
                .lookup("ssh")
                .profile
                .map(CommandProfile::primary_name),
            Some("ssh")
        );
        assert_eq!(
            registry
                .lookup("sed")
                .profile
                .map(CommandProfile::primary_name),
            Some("sed")
        );
        assert_eq!(
            registry
                .lookup("sudo")
                .profile
                .map(CommandProfile::primary_name),
            Some("sudo")
        );
        assert_eq!(
            registry
                .lookup("tar")
                .profile
                .map(CommandProfile::primary_name),
            Some("tar")
        );
        assert_eq!(
            registry
                .lookup("tee")
                .profile
                .map(CommandProfile::primary_name),
            Some("tee")
        );
        assert_eq!(
            registry
                .lookup("stdbuf")
                .profile
                .map(CommandProfile::primary_name),
            Some("stdbuf")
        );
        assert_eq!(
            registry
                .lookup("shred")
                .profile
                .map(CommandProfile::primary_name),
            Some("shred")
        );
        assert_eq!(
            registry
                .lookup("timeout")
                .profile
                .map(CommandProfile::primary_name),
            Some("timeout")
        );
        assert_eq!(
            registry
                .lookup("unzip")
                .profile
                .map(CommandProfile::primary_name),
            Some("unzip")
        );
        assert_eq!(
            registry
                .lookup("wget")
                .profile
                .map(CommandProfile::primary_name),
            Some("wget")
        );
        assert_eq!(
            registry
                .lookup("wipefs")
                .profile
                .map(CommandProfile::primary_name),
            Some("wipefs")
        );
        assert_eq!(
            registry
                .lookup("xxd")
                .profile
                .map(CommandProfile::primary_name),
            Some("xxd")
        );
        assert_eq!(
            registry
                .lookup("xargs")
                .profile
                .map(CommandProfile::primary_name),
            Some("xargs")
        );
        assert_eq!(
            registry
                .lookup(r"\sh-compatible")
                .profile
                .map(CommandProfile::primary_name),
            Some("bash")
        );
        assert_eq!(
            registry
                .lookup("unalias")
                .profile
                .map(CommandProfile::primary_name),
            Some("unalias")
        );
    }
}
