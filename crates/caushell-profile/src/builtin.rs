use crate::{LoadProfileError, ProfileRegistry, RegistryError, load_command_profile_from_str};

struct BuiltInProfileSource {
    profile_id: &'static str,
    content: &'static str,
}

const BUILT_IN_PROFILE_SOURCES: &[BuiltInProfileSource] = &[
    BuiltInProfileSource {
        profile_id: "autoconf",
        content: include_str!("../profiles/autoconf.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "autoheader",
        content: include_str!("../profiles/autoheader.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "autoreconf",
        content: include_str!("../profiles/autoreconf.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "bundle",
        content: include_str!("../profiles/bundle.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "bundler",
        content: include_str!("../profiles/bundler.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "cabal",
        content: include_str!("../profiles/cabal.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "cobc",
        content: include_str!("../profiles/cobc.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "composer",
        content: include_str!("../profiles/composer.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "easy_install",
        content: include_str!("../profiles/easy_install.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "exiftool",
        content: include_str!("../profiles/exiftool.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "gem",
        content: include_str!("../profiles/gem.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "go",
        content: include_str!("../profiles/go.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "java",
        content: include_str!("../profiles/java.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "jjs",
        content: include_str!("../profiles/jjs.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "jrunscript",
        content: include_str!("../profiles/jrunscript.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "latex",
        content: include_str!("../profiles/latex.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "latexmk",
        content: include_str!("../profiles/latexmk.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "lualatex",
        content: include_str!("../profiles/lualatex.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "luatex",
        content: include_str!("../profiles/luatex.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "msfconsole",
        content: include_str!("../profiles/msfconsole.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pdflatex",
        content: include_str!("../profiles/pdflatex.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pdftex",
        content: include_str!("../profiles/pdftex.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "puppet",
        content: include_str!("../profiles/puppet.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rake",
        content: include_str!("../profiles/rake.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rustc",
        content: include_str!("../profiles/rustc.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rustdoc",
        content: include_str!("../profiles/rustdoc.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tex",
        content: include_str!("../profiles/tex.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "vagrant",
        content: include_str!("../profiles/vagrant.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "xelatex",
        content: include_str!("../profiles/xelatex.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "xetex",
        content: include_str!("../profiles/xetex.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "codex",
        content: include_str!("../profiles/codex.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "opencode",
        content: include_str!("../profiles/opencode.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ffmpeg",
        content: include_str!("../profiles/ffmpeg.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "apache2",
        content: include_str!("../profiles/apache2.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "apache2ctl",
        content: include_str!("../profiles/apache2ctl.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "aws",
        content: include_str!("../profiles/aws.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "busctl",
        content: include_str!("../profiles/busctl.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ctr",
        content: include_str!("../profiles/ctr.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dmsetup",
        content: include_str!("../profiles/dmsetup.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dstat",
        content: include_str!("../profiles/dstat.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "easyrsa",
        content: include_str!("../profiles/easyrsa.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "fail2ban-client",
        content: include_str!("../profiles/fail2ban-client.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "hg",
        content: include_str!("../profiles/hg.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ip",
        content: include_str!("../profiles/ip.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "kubectl",
        content: include_str!("../profiles/kubectl.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "loginctl",
        content: include_str!("../profiles/loginctl.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "lxd",
        content: include_str!("../profiles/lxd.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mosh-server",
        content: include_str!("../profiles/mosh-server.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "needrestart",
        content: include_str!("../profiles/needrestart.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "nginx",
        content: include_str!("../profiles/nginx.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "opkg",
        content: include_str!("../profiles/opkg.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "passwd",
        content: include_str!("../profiles/passwd.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "plymouth",
        content: include_str!("../profiles/plymouth.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "podman",
        content: include_str!("../profiles/podman.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "procmail",
        content: include_str!("../profiles/procmail.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rsyslogd",
        content: include_str!("../profiles/rsyslogd.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "service",
        content: include_str!("../profiles/service.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "snap",
        content: include_str!("../profiles/snap.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "systemctl",
        content: include_str!("../profiles/systemctl.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "systemd-resolve",
        content: include_str!("../profiles/systemd-resolve.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tailscale",
        content: include_str!("../profiles/tailscale.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "timedatectl",
        content: include_str!("../profiles/timedatectl.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "unsquashfs",
        content: include_str!("../profiles/unsquashfs.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "virsh",
        content: include_str!("../profiles/virsh.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "wg-quick",
        content: include_str!("../profiles/wg-quick.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "crash",
        content: include_str!("../profiles/crash.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "emacs",
        content: include_str!("../profiles/emacs.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ex",
        content: include_str!("../profiles/ex.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ftp",
        content: include_str!("../profiles/ftp.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "gdb",
        content: include_str!("../profiles/gdb.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "gimp",
        content: include_str!("../profiles/gimp.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ksh",
        content: include_str!("../profiles/ksh.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "lftp",
        content: include_str!("../profiles/lftp.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ncftp",
        content: include_str!("../profiles/ncftp.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "nvim",
        content: include_str!("../profiles/nvim.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pico",
        content: include_str!("../profiles/pico.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "posh",
        content: include_str!("../profiles/posh.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "psftp",
        content: include_str!("../profiles/psftp.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rc",
        content: include_str!("../profiles/rc.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "red",
        content: include_str!("../profiles/red.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rlogin",
        content: include_str!("../profiles/rlogin.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rtorrent",
        content: include_str!("../profiles/rtorrent.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "run-mailcap",
        content: include_str!("../profiles/run-mailcap.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rview",
        content: include_str!("../profiles/rview.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rvim",
        content: include_str!("../profiles/rvim.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sash",
        content: include_str!("../profiles/sash.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sftp",
        content: include_str!("../profiles/sftp.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "smbclient",
        content: include_str!("../profiles/smbclient.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "socat",
        content: include_str!("../profiles/socat.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sshfs",
        content: include_str!("../profiles/sshfs.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "view",
        content: include_str!("../profiles/view.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "vigr",
        content: include_str!("../profiles/vigr.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "vimdiff",
        content: include_str!("../profiles/vimdiff.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "vipw",
        content: include_str!("../profiles/vipw.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "wireshark",
        content: include_str!("../profiles/wireshark.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "yash",
        content: include_str!("../profiles/yash.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "irb",
        content: include_str!("../profiles/irb.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pry",
        content: include_str!("../profiles/pry.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "byebug",
        content: include_str!("../profiles/byebug.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "cpan",
        content: include_str!("../profiles/cpan.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ghc",
        content: include_str!("../profiles/ghc.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ghci",
        content: include_str!("../profiles/ghci.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "slsh",
        content: include_str!("../profiles/slsh.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "octave",
        content: include_str!("../profiles/octave.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "jshell",
        content: include_str!("../profiles/jshell.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dotnet",
        content: include_str!("../profiles/dotnet.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ansible-test",
        content: include_str!("../profiles/ansible-test.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "cdist",
        content: include_str!("../profiles/cdist.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "check_ssl_cert",
        content: include_str!("../profiles/check_ssl_cert.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dhclient",
        content: include_str!("../profiles/dhclient.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dnsmasq",
        content: include_str!("../profiles/dnsmasq.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pdb",
        content: include_str!("../profiles/pdb.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "hping3",
        content: include_str!("../profiles/hping3.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "yt-dlp",
        content: include_str!("../profiles/yt-dlp.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "certbot",
        content: include_str!("../profiles/certbot.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "bpftrace",
        content: include_str!("../profiles/bpftrace.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ansible-playbook",
        content: include_str!("../profiles/ansible-playbook.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "bee",
        content: include_str!("../profiles/bee.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sqlmap",
        content: include_str!("../profiles/sqlmap.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "gcloud",
        content: include_str!("../profiles/gcloud.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "eb",
        content: include_str!("../profiles/eb.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "poetry",
        content: include_str!("../profiles/poetry.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pipx",
        content: include_str!("../profiles/pipx.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "knife",
        content: include_str!("../profiles/knife.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "volatility",
        content: include_str!("../profiles/volatility.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "forge",
        content: include_str!("../profiles/forge.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "apport-cli",
        content: include_str!("../profiles/apport-cli.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "asterisk",
        content: include_str!("../profiles/asterisk.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "bconsole",
        content: include_str!("../profiles/bconsole.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "debugfs",
        content: include_str!("../profiles/debugfs.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ginsh",
        content: include_str!("../profiles/ginsh.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "iftop",
        content: include_str!("../profiles/iftop.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "jtag",
        content: include_str!("../profiles/jtag.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "minicom",
        content: include_str!("../profiles/minicom.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "scanmem",
        content: include_str!("../profiles/scanmem.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tdbtool",
        content: include_str!("../profiles/tdbtool.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "apt",
        content: include_str!("../profiles/apt.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "aptitude",
        content: include_str!("../profiles/aptitude.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dpkg",
        content: include_str!("../profiles/dpkg.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dnf",
        content: include_str!("../profiles/dnf.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "zypper",
        content: include_str!("../profiles/zypper.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rpm",
        content: include_str!("../profiles/rpm.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rpmdb",
        content: include_str!("../profiles/rpmdb.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rpmquery",
        content: include_str!("../profiles/rpmquery.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rpmverify",
        content: include_str!("../profiles/rpmverify.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pkg",
        content: include_str!("../profiles/pkg.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "lua",
        content: include_str!("../profiles/lua.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ruby",
        content: include_str!("../profiles/ruby.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "php",
        content: include_str!("../profiles/php.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "guile",
        content: include_str!("../profiles/guile.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tclsh",
        content: include_str!("../profiles/tclsh.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "wish",
        content: include_str!("../profiles/wish.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "clisp",
        content: include_str!("../profiles/clisp.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "R",
        content: include_str!("../profiles/R.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "julia",
        content: include_str!("../profiles/julia.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pwsh",
        content: include_str!("../profiles/pwsh.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "batcat",
        content: include_str!("../profiles/batcat.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pg",
        content: include_str!("../profiles/pg.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "joe",
        content: include_str!("../profiles/joe.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ispell",
        content: include_str!("../profiles/ispell.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ncdu",
        content: include_str!("../profiles/ncdu.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ranger",
        content: include_str!("../profiles/ranger.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "zathura",
        content: include_str!("../profiles/zathura.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "journalctl",
        content: include_str!("../profiles/journalctl.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "fastfetch",
        content: include_str!("../profiles/fastfetch.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "neofetch",
        content: include_str!("../profiles/neofetch.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "lp",
        content: include_str!("../profiles/lp.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "cancel",
        content: include_str!("../profiles/cancel.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "telnet",
        content: include_str!("../profiles/telnet.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tftp",
        content: include_str!("../profiles/tftp.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "socket",
        content: include_str!("../profiles/socket.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ltrace",
        content: include_str!("../profiles/ltrace.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tshark",
        content: include_str!("../profiles/tshark.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "nmap",
        content: include_str!("../profiles/nmap.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tmate",
        content: include_str!("../profiles/tmate.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "openvpn",
        content: include_str!("../profiles/openvpn.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dc",
        content: include_str!("../profiles/dc.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "gnuplot",
        content: include_str!("../profiles/gnuplot.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "elvish",
        content: include_str!("../profiles/elvish.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dosbox",
        content: include_str!("../profiles/dosbox.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "csvtool",
        content: include_str!("../profiles/csvtool.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "facter",
        content: include_str!("../profiles/facter.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "expect",
        content: include_str!("../profiles/expect.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "csh",
        content: include_str!("../profiles/csh.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tcsh",
        content: include_str!("../profiles/tcsh.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "fish",
        content: include_str!("../profiles/fish.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "aria2c",
        content: include_str!("../profiles/aria2c.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tcpdump",
        content: include_str!("../profiles/tcpdump.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "restic",
        content: include_str!("../profiles/restic.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "borg",
        content: include_str!("../profiles/borg.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "logrotate",
        content: include_str!("../profiles/logrotate.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dmidecode",
        content: include_str!("../profiles/dmidecode.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ldconfig",
        content: include_str!("../profiles/ldconfig.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "update-alternatives",
        content: include_str!("../profiles/update-alternatives.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "varnishncsa",
        content: include_str!("../profiles/varnishncsa.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "hashcat",
        content: include_str!("../profiles/hashcat.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "arj",
        content: include_str!("../profiles/arj.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "links",
        content: include_str!("../profiles/links.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "w3m",
        content: include_str!("../profiles/w3m.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "xmore",
        content: include_str!("../profiles/xmore.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "xpad",
        content: include_str!("../profiles/xpad.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "yelp",
        content: include_str!("../profiles/yelp.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "alpine",
        content: include_str!("../profiles/alpine.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mutt",
        content: include_str!("../profiles/mutt.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "urlget",
        content: include_str!("../profiles/urlget.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pandoc",
        content: include_str!("../profiles/pandoc.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "acr",
        content: include_str!("../profiles/acr.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "agetty",
        content: include_str!("../profiles/agetty.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "task",
        content: include_str!("../profiles/task.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tasksh",
        content: include_str!("../profiles/tasksh.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "xdotool",
        content: include_str!("../profiles/xdotool.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "at",
        content: include_str!("../profiles/at.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "zic",
        content: include_str!("../profiles/zic.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "runscript",
        content: include_str!("../profiles/runscript.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "gtester",
        content: include_str!("../profiles/gtester.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "zip",
        content: include_str!("../profiles/zip.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "arch-nspawn",
        content: include_str!("../profiles/arch-nspawn.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "genie",
        content: include_str!("../profiles/genie.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rustup",
        content: include_str!("../profiles/rustup.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "fzf",
        content: include_str!("../profiles/fzf.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "scrot",
        content: include_str!("../profiles/scrot.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pidstat",
        content: include_str!("../profiles/pidstat.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sshuttle",
        content: include_str!("../profiles/sshuttle.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "xdg-user-dir",
        content: include_str!("../profiles/xdg-user-dir.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "cowsay",
        content: include_str!("../profiles/cowsay.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "arp",
        content: include_str!("../profiles/arp.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "bridge",
        content: include_str!("../profiles/bridge.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "nft",
        content: include_str!("../profiles/nft.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "iptables-save",
        content: include_str!("../profiles/iptables-save.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "clamscan",
        content: include_str!("../profiles/clamscan.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dmesg",
        content: include_str!("../profiles/dmesg.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "gcore",
        content: include_str!("../profiles/gcore.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sysctl",
        content: include_str!("../profiles/sysctl.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ssh-copy-id",
        content: include_str!("../profiles/ssh-copy-id.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "whois",
        content: include_str!("../profiles/whois.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "troff",
        content: include_str!("../profiles/troff.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "nroff",
        content: include_str!("../profiles/nroff.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pic",
        content: include_str!("../profiles/pic.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "m4",
        content: include_str!("../profiles/m4.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "msgfilter",
        content: include_str!("../profiles/msgfilter.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dvips",
        content: include_str!("../profiles/dvips.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "enscript",
        content: include_str!("../profiles/enscript.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "zgrep",
        content: include_str!("../profiles/zgrep.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "rustfmt",
        content: include_str!("../profiles/rustfmt.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tsc",
        content: include_str!("../profiles/tsc.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ntpdate",
        content: include_str!("../profiles/ntpdate.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "check_cups",
        content: include_str!("../profiles/check_cups.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "check_memory",
        content: include_str!("../profiles/check_memory.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "check_raid",
        content: include_str!("../profiles/check_raid.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "bbot",
        content: include_str!("../profiles/bbot.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mosquitto",
        content: include_str!("../profiles/mosquitto.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ksshell",
        content: include_str!("../profiles/ksshell.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "terraform",
        content: include_str!("../profiles/terraform.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "xmodmap",
        content: include_str!("../profiles/xmodmap.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "7z",
        content: include_str!("../profiles/7z.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "zsoelim",
        content: include_str!("../profiles/zsoelim.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mtr",
        content: include_str!("../profiles/mtr.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "nasm",
        content: include_str!("../profiles/nasm.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tic",
        content: include_str!("../profiles/tic.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pax",
        content: include_str!("../profiles/pax.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "genisoimage",
        content: include_str!("../profiles/genisoimage.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "aspell",
        content: include_str!("../profiles/aspell.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "qpdf",
        content: include_str!("../profiles/qpdf.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mawk",
        content: include_str!("../profiles/mawk.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "run-parts",
        content: include_str!("../profiles/run-parts.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "start-stop-daemon",
        content: include_str!("../profiles/start-stop-daemon.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ld.so",
        content: include_str!("../profiles/ld.so.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "check_by_ssh",
        content: include_str!("../profiles/check_by_ssh.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "perlbug",
        content: include_str!("../profiles/perlbug.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "bashbug",
        content: include_str!("../profiles/bashbug.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ssh-agent",
        content: include_str!("../profiles/ssh-agent.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "distcc",
        content: include_str!("../profiles/distcc.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pkexec",
        content: include_str!("../profiles/pkexec.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pexec",
        content: include_str!("../profiles/pexec.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "grc",
        content: include_str!("../profiles/grc.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "capsh",
        content: include_str!("../profiles/capsh.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "chroot",
        content: include_str!("../profiles/chroot.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "openvt",
        content: include_str!("../profiles/openvt.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ksu",
        content: include_str!("../profiles/ksu.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sg",
        content: include_str!("../profiles/sg.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dos2unix",
        content: include_str!("../profiles/dos2unix.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ssh-keyscan",
        content: include_str!("../profiles/ssh-keyscan.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ab",
        content: include_str!("../profiles/ab.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "lwp-request",
        content: include_str!("../profiles/lwp-request.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "lwp-download",
        content: include_str!("../profiles/lwp-download.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "check_log",
        content: include_str!("../profiles/check_log.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "check_statusfile",
        content: include_str!("../profiles/check_statusfile.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "as",
        content: include_str!("../profiles/as.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "efax",
        content: include_str!("../profiles/efax.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "fping",
        content: include_str!("../profiles/fping.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "msgattrib",
        content: include_str!("../profiles/msgattrib.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "msgcat",
        content: include_str!("../profiles/msgcat.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "msgconv",
        content: include_str!("../profiles/msgconv.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "msgmerge",
        content: include_str!("../profiles/msgmerge.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "msguniq",
        content: include_str!("../profiles/msguniq.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "readelf",
        content: include_str!("../profiles/readelf.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "highlight",
        content: include_str!("../profiles/highlight.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "espeak",
        content: include_str!("../profiles/espeak.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "atobm",
        content: include_str!("../profiles/atobm.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "redcarpet",
        content: include_str!("../profiles/redcarpet.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "xz",
        content: include_str!("../profiles/xz.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "chattr",
        content: include_str!("../profiles/chattr.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "setcap",
        content: include_str!("../profiles/setcap.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "setfacl",
        content: include_str!("../profiles/setfacl.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "wall",
        content: include_str!("../profiles/wall.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "dialog",
        content: include_str!("../profiles/dialog.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "whiptail",
        content: include_str!("../profiles/whiptail.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "eqn",
        content: include_str!("../profiles/eqn.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "tbl",
        content: include_str!("../profiles/tbl.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "soelim",
        content: include_str!("../profiles/soelim.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "uudecode",
        content: include_str!("../profiles/uudecode.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "look",
        content: include_str!("../profiles/look.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ul",
        content: include_str!("../profiles/ul.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "uuencode",
        content: include_str!("../profiles/uuencode.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ascii85",
        content: include_str!("../profiles/ascii85.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "base58",
        content: include_str!("../profiles/base58.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "basez",
        content: include_str!("../profiles/basez.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ascii-xfr",
        content: include_str!("../profiles/ascii-xfr.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "last",
        content: include_str!("../profiles/last.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "nm",
        content: include_str!("../profiles/nm.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "cupsfilter",
        content: include_str!("../profiles/cupsfilter.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "aa-exec",
        content: include_str!("../profiles/aa-exec.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "aoss",
        content: include_str!("../profiles/aoss.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "choom",
        content: include_str!("../profiles/choom.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "cpulimit",
        content: include_str!("../profiles/cpulimit.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "multitime",
        content: include_str!("../profiles/multitime.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "setarch",
        content: include_str!("../profiles/setarch.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "softlimit",
        content: include_str!("../profiles/softlimit.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "torify",
        content: include_str!("../profiles/torify.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "torsocks",
        content: include_str!("../profiles/torsocks.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "logsave",
        content: include_str!("../profiles/logsave.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ar",
        content: include_str!("../profiles/ar.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "basenc",
        content: include_str!("../profiles/basenc.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "setlock",
        content: include_str!("../profiles/setlock.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "disown",
        content: include_str!("../profiles/disown.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "exit",
        content: include_str!("../profiles/exit.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "wait",
        content: include_str!("../profiles/wait.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "py_compile",
        content: include_str!("../profiles/py_compile.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "compileall",
        content: include_str!("../profiles/compileall.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "json.tool",
        content: include_str!("../profiles/json.tool.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "http.server",
        content: include_str!("../profiles/http.server.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mysql",
        content: include_str!("../profiles/mysql.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "mail",
        content: include_str!("../profiles/mail.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pv",
        content: include_str!("../profiles/pv.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "lsof",
        content: include_str!("../profiles/lsof.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "brew",
        content: include_str!("../profiles/brew.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "yum",
        content: include_str!("../profiles/yum.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "screen",
        content: include_str!("../profiles/screen.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "redis-cli",
        content: include_str!("../profiles/redis-cli.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "apply_patch",
        content: include_str!("../profiles/apply_patch.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ss",
        content: include_str!("../profiles/ss.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sqlite3",
        content: include_str!("../profiles/sqlite3.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "nsys",
        content: include_str!("../profiles/nsys.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "ruff",
        content: include_str!("../profiles/ruff.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "uv",
        content: include_str!("../profiles/uv.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "uvicorn",
        content: include_str!("../profiles/uvicorn.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "conda",
        content: include_str!("../profiles/conda.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pytest",
        content: include_str!("../profiles/pytest.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "nvidia-smi",
        content: include_str!("../profiles/nvidia-smi.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "sshpass",
        content: include_str!("../profiles/sshpass.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "getent",
        content: include_str!("../profiles/getent.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "bc",
        content: include_str!("../profiles/bc.yaml"),
    },
    BuiltInProfileSource {
        profile_id: "pdftotext",
        content: include_str!("../profiles/pdftotext.yaml"),
    },
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
        profile_id: "fd",
        content: include_str!("../profiles/fd.yaml"),
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
        profile_id: "parallel",
        content: include_str!("../profiles/parallel.yaml"),
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
