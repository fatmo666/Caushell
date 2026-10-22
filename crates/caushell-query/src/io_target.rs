//! Pure semantic query over a statically projected descriptor snapshot.
//! It never probes descriptors, follows host symlinks, or labels streams safe.
use std::collections::BTreeMap;

use caushell_types::PathResolution;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoTarget {
    /// A shell-opened socket address, not a pathname or a host FD observation.
    Network {
        endpoint: Option<String>,
    },
    Path {
        resolution: PathResolution,
        cwd_dependent: bool,
    },
    InheritedDescriptor {
        descriptor: String,
    },
    InlineContent {
        redirection_index: usize,
    },
    ProcessSubstitution {
        redirection_index: usize,
    },
    UnknownDescriptor {
        descriptor: String,
    },
    Closed,
    Discard,
}

pub struct IoTargetQuery;

impl IoTargetQuery {
    /// Already-decoded Bash redirect spelling, BEFORE filesystem normalization.
    /// Bash's special open pattern is /dev/{tcp,udp}/*/*, not a path alias.
    pub fn bash_network_redirection(spelling: &str) -> Option<IoTarget> {
        let rest = spelling
            .strip_prefix("/dev/tcp/")
            .or_else(|| spelling.strip_prefix("/dev/udp/"))?;
        let (host, service) = rest.split_once('/')?;
        let host = if host.parse::<std::net::Ipv6Addr>().is_ok() {
            Some(format!("[{host}]"))
        } else if !host.is_empty()
            && host
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
        {
            Some(host.to_string())
        } else {
            None
        };
        let service_known = !service.is_empty()
            && service
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'));
        Some(IoTarget::Network {
            endpoint: host
                .filter(|_| service_known)
                .map(|host| format!("{host}:{service}")),
        })
    }
    /// Only exact same-process aliases; no arbitrary /dev or /proc exemption.
    pub fn descriptor_alias(path: &str) -> Option<&str> {
        match path {
            "/dev/stdin" => Some("0"),
            "/dev/stdout" => Some("1"),
            "/dev/stderr" => Some("2"),
            _ => path
                .strip_prefix("/dev/fd/")
                .or_else(|| path.strip_prefix("/proc/self/fd/"))
                .and_then(Self::canonical_descriptor),
        }
    }

    pub fn canonical_descriptor(text: &str) -> Option<&str> {
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let significant = text.trim_start_matches('0');
        Some(if significant.is_empty() {
            "0"
        } else {
            significant
        })
    }

    pub fn descriptor(descriptor: &str, snapshot: &BTreeMap<String, IoTarget>) -> IoTarget {
        let Some(descriptor) = Self::canonical_descriptor(descriptor) else {
            return IoTarget::UnknownDescriptor {
                descriptor: descriptor.into(),
            };
        };
        snapshot.get(descriptor).cloned().unwrap_or_else(|| {
            if matches!(descriptor, "0" | "1" | "2") {
                IoTarget::InheritedDescriptor {
                    descriptor: descriptor.into(),
                }
            } else {
                IoTarget::UnknownDescriptor {
                    descriptor: descriptor.into(),
                }
            }
        })
    }

    pub fn content_path(
        resolution: &PathResolution,
        cwd_dependent: bool,
        snapshot: &BTreeMap<String, IoTarget>,
    ) -> IoTarget {
        match resolution.concrete_path() {
            Some("/dev/null") => IoTarget::Discard,
            Some(path) => match Self::descriptor_alias(path) {
                Some(descriptor) => Self::descriptor(descriptor, snapshot),
                None => IoTarget::Path {
                    resolution: resolution.clone(),
                    cwd_dependent,
                },
            },
            None => IoTarget::Path {
                resolution: resolution.clone(),
                cwd_dependent,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_are_exact_and_self_only() {
        for (path, fd) in [
            ("/dev/stdin", "0"),
            ("/dev/stdout", "1"),
            ("/dev/stderr", "2"),
            ("/dev/fd/003", "3"),
            ("/proc/self/fd/01", "1"),
        ] {
            assert_eq!(IoTargetQuery::descriptor_alias(path), Some(fd));
        }
        for path in [
            "/dev/fd/",
            "/dev/fd/-1",
            "/dev/fd/$fd",
            "/dev/fd/3/x",
            "/proc/123/fd/1",
            "/dev/stdout-other",
            "/dev/tty",
            "/dev/sda",
        ] {
            assert_eq!(IoTargetQuery::descriptor_alias(path), None, "{path}");
        }
    }

    #[test]
    fn bash_socket_open_uses_native_spelling_without_path_normalization() {
        for (spelling, endpoint) in [
            ("/dev/tcp/127.0.0.1/80", "127.0.0.1:80"),
            ("/dev/udp/localhost/domain", "localhost:domain"),
            ("/dev/tcp/::1/80", "[::1]:80"),
            ("/dev/tcp/collector.example/443", "collector.example:443"),
        ] {
            assert_eq!(
                IoTargetQuery::bash_network_redirection(spelling),
                Some(IoTarget::Network {
                    endpoint: Some(endpoint.into())
                })
            );
        }
        for spelling in [
            "/tmp/../dev/tcp/127.0.0.1/80",
            "/dev//tcp/127.0.0.1/80",
            "/dev/tcp/localhost",
            "./dev/tcp/localhost/80",
            "/dev/tcpish/localhost/80",
        ] {
            assert_eq!(IoTargetQuery::bash_network_redirection(spelling), None);
        }
        for spelling in [
            "/dev/tcp/evil@127.0.0.1/80",
            "/dev/tcp/localhost/80/../out",
            "/dev/tcp/$HOST/80",
        ] {
            assert_eq!(
                IoTargetQuery::bash_network_redirection(spelling),
                Some(IoTarget::Network { endpoint: None })
            );
        }
    }

    #[test]
    fn nonstandard_descriptors_are_unknown_and_known_targets_are_preserved() {
        let mut snapshot = BTreeMap::new();
        assert_eq!(
            IoTargetQuery::descriptor("3", &snapshot),
            IoTarget::UnknownDescriptor {
                descriptor: "3".into()
            }
        );
        snapshot.insert(
            "1".into(),
            IoTarget::Path {
                resolution: PathResolution::Concrete {
                    path: "/opt/shared/out".into(),
                },
                cwd_dependent: false,
            },
        );
        let resolution = PathResolution::Concrete {
            path: "/dev/stdout".into(),
        };
        assert_eq!(
            IoTargetQuery::content_path(&resolution, false, &snapshot),
            snapshot["1"]
        );
        snapshot.insert("1".into(), IoTarget::Closed);
        assert_eq!(
            IoTargetQuery::content_path(&resolution, false, &snapshot),
            IoTarget::Closed
        );
    }
}
