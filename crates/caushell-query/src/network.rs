//! Declared network endpoints and lexical destination scope. No DNS or I/O.
use caushell_graph::{EdgeKind, GraphRead, NodeId, NodeKind};
use caushell_types::{
    CommandSequenceNo, ProvenanceArtifact, ProvenanceEndpointKind, ProvenanceEndpointUsage,
};

pub struct NetworkEndpointRef<'a> {
    pub execution_node_id: &'a NodeId,
    pub command: &'a str,
    pub endpoint: &'a str,
    pub kind: ProvenanceEndpointKind,
    pub usage: ProvenanceEndpointUsage,
    pub input_scope: Option<(Vec<String>, bool)>,
}

pub struct NetworkEndpointQuery;

impl NetworkEndpointQuery {
    /// A loopback URL is not a local-route proof when the same execution has
    /// a declared nonlocal or unresolved transport override.
    pub fn has_nonlocal_transport_target(graph: &dyn GraphRead, execution: &NodeId) -> bool {
        graph.outgoing_edges(execution).any(|edge| edge.kind == EdgeKind::Consumes
            && matches!(&edge.semantics, Some(caushell_types::ProvenanceEdgeSemantics::Consume {consume_kind: caushell_types::ProvenanceConsumeKind::NetworkEndpoint, ..}))
            && graph.get_node(&edge.to).is_some_and(|node| matches!(&node.kind, NodeKind::ProvenanceArtifact {artifact: ProvenanceArtifact::NetworkEndpoint {endpoint, endpoint_kind, usage: ProvenanceEndpointUsage::TransportTarget}} if !endpoint_has_loopback_scope(endpoint, *endpoint_kind))))
    }
    /// Walk only supplied execution units, including partial and derived calls.
    pub fn for_execution_units<'a>(
        graph: &'a dyn GraphRead,
        nodes: &[NodeId],
        sequence: CommandSequenceNo,
    ) -> Vec<NetworkEndpointRef<'a>> {
        let mut result = Vec::new();
        for id in nodes {
            let Some(node) = graph.get_node(id) else {
                continue;
            };
            let command = match &node.kind {
                NodeKind::CommandInvocation {
                    sequence_no,
                    raw_text,
                    ..
                } if *sequence_no == sequence => raw_text,
                NodeKind::DerivedInvocation {
                    root_command_sequence_no,
                    raw_text,
                    ..
                } if *root_command_sequence_no == sequence => raw_text,
                _ => continue,
            };
            for edge in graph.outgoing_edges(id).filter(|edge| {
                edge.kind == EdgeKind::Consumes
                    && matches!(
                        &edge.semantics,
                        Some(caushell_types::ProvenanceEdgeSemantics::Consume {
                            consume_kind: caushell_types::ProvenanceConsumeKind::NetworkEndpoint,
                            ..
                        })
                    )
            }) {
                let Some(NodeKind::ProvenanceArtifact {
                    artifact:
                        ProvenanceArtifact::NetworkEndpoint {
                            endpoint,
                            endpoint_kind,
                            usage,
                        },
                }) = graph.get_node(&edge.to).map(|node| &node.kind)
                else {
                    continue;
                };
                result.push(NetworkEndpointRef {
                    execution_node_id: &node.id,
                    command,
                    endpoint,
                    kind: *endpoint_kind,
                    usage: *usage,
                    input_scope: match &edge.semantics {
                        Some(caushell_types::ProvenanceEdgeSemantics::Consume {
                            domain_label:
                                Some(caushell_types::ProvenanceDomainLabel::EndpointInputScope {
                                    slots,
                                    stdin,
                                }),
                            ..
                        }) => Some((slots.clone(), *stdin)),
                        _ => None,
                    },
                });
            }
        }
        result
    }

    /// Follow actual request-byte lineage with existing stream dependency and
    /// auxiliary-input gates. A bound is not an expanded filename.
    pub fn local_request_source(
        graph: &dyn GraphRead,
        endpoint: &NetworkEndpointRef<'_>,
        max_hops: u32,
        max_nodes: usize,
    ) -> Result<Option<String>, &'static str> {
        use std::collections::{BTreeSet, VecDeque};
        let mut queue: VecDeque<_> = crate::DataDependencyQuery::request_input_artifacts(
            graph,
            endpoint.execution_node_id,
            endpoint.input_scope.as_ref(),
        )
        .into_iter()
        .map(|id| (id, true, 0))
        .collect();
        let mut visited = BTreeSet::new();
        while let Some((id, artifact, depth)) = queue.pop_front() {
            if !visited.insert((id.clone(), artifact)) {
                continue;
            }
            if visited.len() > max_nodes {
                return Err("request-data lineage exceeds the node budget");
            }
            if artifact {
                match graph.get_node(&id).map(|n| &n.kind) {
                    Some(NodeKind::ProvenanceArtifact {
                        artifact: ProvenanceArtifact::PathContent { path, .. },
                    }) => return Ok(Some(path.clone())),
                    Some(NodeKind::ProvenanceArtifact {
                        artifact:
                            ProvenanceArtifact::PathSelectionContent {
                                resolution,
                                selector,
                            },
                    }) => {
                        return Ok(Some(
                            selector
                                .clone()
                                .unwrap_or_else(|| format!("{resolution:?}")),
                        ));
                    }
                    Some(NodeKind::ProvenanceArtifact {
                        artifact: ProvenanceArtifact::PathFamily { directory, prefix },
                    }) => return Ok(Some(format!("{directory}/{prefix}*"))),
                    // The URL itself is not the origin of locally read bytes.
                    Some(NodeKind::ProvenanceArtifact {
                        artifact: ProvenanceArtifact::NetworkEndpoint { .. },
                    }) => continue,
                    _ => {}
                }
            }
            let next = if artifact {
                crate::DataDependencyQuery::input_producers(graph, &id)
            } else {
                crate::DataDependencyQuery::input_artifacts(graph, &id)
            };
            if depth >= max_hops && !next.is_empty() {
                return Err("request-data lineage exceeds the hop budget");
            }
            queue.extend(next.into_iter().map(|id| (id, !artifact, depth + 1)));
        }
        Ok(None)
    }
}

/// Only a statically spelled loopback destination qualifies. A substring,
/// unresolved expansion, ambiguous authority or recipient domain does not.
pub fn endpoint_has_loopback_scope(endpoint: &str, kind: ProvenanceEndpointKind) -> bool {
    if endpoint.is_empty()
        || endpoint.len() > 8192
        || endpoint.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '$' | '`' | '\\' | '\'' | '"')
        })
    {
        return false;
    }
    match kind {
        ProvenanceEndpointKind::Url => url_host(endpoint).is_some_and(loopback_host),
        ProvenanceEndpointKind::HostPort => host_port(endpoint).is_some_and(loopback_host),
        ProvenanceEndpointKind::RemoteSpec => {
            if endpoint.starts_with("rsync://") {
                return url_host(endpoint).is_some_and(loopback_host);
            }
            // Username syntax belongs to the peer, not a later @ in the path.
            let peer = match endpoint.find('@') {
                Some(index) if !endpoint[..index].contains([':', '/', '[', ']']) => {
                    &endpoint[index + 1..]
                }
                _ => endpoint,
            };
            let host = if let Some(rest) = peer.strip_prefix('[') {
                rest.split_once(']')
                    .filter(|(host, tail)| {
                        tail.starts_with(':') && host.parse::<std::net::Ipv6Addr>().is_ok()
                    })
                    .map(|(host, _)| host)
            } else {
                peer.split_once(':').map(|(host, _)| host)
            };
            host.is_some_and(loopback_host)
        }
        // A mail recipient is not the SMTP transport destination. A socket
        // path qualifies only when it is an absolute filesystem path.
        ProvenanceEndpointKind::EmailAddress => false,
        ProvenanceEndpointKind::SocketPath => endpoint.starts_with('/'),
    }
}

fn url_host(endpoint: &str) -> Option<&str> {
    let (scheme, tail) = endpoint.split_once("://")?;
    if scheme.is_empty()
        || !scheme.as_bytes()[0].is_ascii_alphabetic()
        || !scheme
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
    {
        return None;
    }
    // Local-file/custom schemes do not establish loopback network transport.
    if ![
        "http", "https", "ftp", "ftps", "sftp", "scp", "ssh", "rsync", "tftp", "ws", "wss", "smtp",
        "smtps", "imap", "imaps", "pop3", "pop3s", "ldap", "ldaps", "rtsp", "socks4", "socks4a",
        "socks5", "socks5h",
    ]
    .iter()
    .any(|known| scheme.eq_ignore_ascii_case(known))
    {
        return None;
    }
    let authority = tail.split(['/', '?', '#']).next()?;
    let peer = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if !peer.starts_with('[') && peer.matches(':').count() > 1 {
        return None;
    }
    host_port(peer)
}

fn host_port(peer: &str) -> Option<&str> {
    if peer.parse::<std::net::IpAddr>().is_ok() {
        return Some(peer);
    }
    if let Some(rest) = peer.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        if !tail.is_empty() && !tail.strip_prefix(':').is_some_and(valid_port) {
            return None;
        }
        return host.parse::<std::net::Ipv6Addr>().ok().map(|_| host);
    }
    match peer.split_once(':') {
        Some((host, port)) if valid_port(port) => Some(host),
        Some(_) => None,
        None => Some(peer),
    }
}

fn valid_port(port: &str) -> bool {
    !port.is_empty() && port.bytes().all(|c| c.is_ascii_digit()) && port.parse::<u16>().is_ok()
}

fn loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback(),
        Ok(std::net::IpAddr::V6(ip)) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scope_depends_on_authority_not_substrings() {
        use ProvenanceEndpointKind::*;
        for (value, kind) in [
            ("http://127.12.3.4:80/x", Url),
            ("http://[::1]:8765/x", Url),
            ("ftp://user@LOCALHOST/x", Url),
            ("socks5h://localhost:1080", Url),
            ("u@[::1]:/x", RemoteSpec),
            ("127.0.0.1::module/x", RemoteSpec),
            ("rsync://localhost/module", RemoteSpec),
            ("localhost:80", HostPort),
            ("[::ffff:127.0.0.1]:80", HostPort),
            ("/tmp/socket", SocketPath),
        ] {
            assert!(endpoint_has_loopback_scope(value, kind), "{value}");
        }
        for (value, kind) in [
            ("https://localhost.evil/x", Url),
            ("http://localhost@evil/x", Url),
            ("http://evil/localhost", Url),
            ("http://127.0.0.1:bad/x", Url),
            ("http://127.0.0.1:99999/x", Url),
            ("http://[::1]evil/x", Url),
            ("http://$HOST/x", Url),
            ("http://$(echo localhost)/x", Url),
            ("http://localhost\\@evil/x", Url),
            ("app1:", RemoteSpec),
            ("evil:/path@localhost:/backup", RemoteSpec),
            ("evil::module/@localhost:/backup", RemoteSpec),
            ("user@evil:/path@localhost:/backup", RemoteSpec),
            ("[localhost]:/backup", RemoteSpec),
            ("file://localhost/etc/file", Url),
            ("custom://localhost/file", Url),
            ("http://::1/file", Url),
            ("user@localhost", EmailAddress),
            ("socket-$X", SocketPath),
            ("127.0.0.1.evil:80", HostPort),
        ] {
            assert!(!endpoint_has_loopback_scope(value, kind), "{value}");
        }
    }
}
