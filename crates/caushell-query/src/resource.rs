use std::net::IpAddr;

/// Exact HTTP resource locator. Hostname resolution and server-specific path
/// normalization require an external contract and are not guessed here.
pub fn canonical_resource_endpoint(value: &str) -> Option<String> {
    if value.len() > 8192 || value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    let (scheme, rest) = value.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let (authority, path) = rest
        .split_once('/')
        .map_or((rest, "/".to_owned()), |(a, p)| (a, format!("/{p}")));
    if path.contains([
        '%', '?', '#', '\\', '$', '`', '\'', '"', '*', '[', ']', '{', '}',
    ]) || path.split('/').any(|s| matches!(s, "." | ".."))
        || path.contains("//")
    {
        return None;
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let ip: std::net::Ipv6Addr = host.parse().ok()?;
        let port = if tail.is_empty() {
            default_port
        } else {
            tail.strip_prefix(':')?.parse::<u16>().ok()?
        };
        (IpAddr::V6(ip), port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().ok()?),
            None => (authority, default_port),
        };
        (IpAddr::V4(host.parse().ok()?), port)
    };
    if port == 0 || host.is_unspecified() || host.is_multicast() {
        return None;
    }
    let host = match host {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };
    Some(format!("{scheme}://{host}:{port}{path}"))
}

/// Origin of a concrete numeric HTTP(S) locator; this does not assert ownership.
pub fn canonical_resource_origin(value: &str) -> Option<String> {
    let endpoint = canonical_resource_endpoint(value)?;
    let end = endpoint.find("://")? + 3;
    let path = end + endpoint[end..].find('/')?;
    Some(endpoint[..=path].to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_locators_do_not_infer_ownership_or_resolve_names() {
        assert_eq!(
            canonical_resource_endpoint("HTTP://127.0.0.1/a").unwrap(),
            "http://127.0.0.1:80/a"
        );
        assert_eq!(
            canonical_resource_endpoint("http://[0:0:0:0:0:0:0:1]:91/a").unwrap(),
            "http://[::1]:91/a"
        );
        for value in [
            "http://localhost/a",
            "http://127.0.0.1@evil/a",
            "http://127.0.0.1/a/../b",
            "http://127.0.0.1/a%2fb",
            "http://127.0.0.1/a?x=1",
            "http://127.0.0.1:0/a",
            "http://0.0.0.0/a",
            "http://127.0.0.1/{a,b}",
        ] {
            assert_eq!(canonical_resource_endpoint(value), None, "{value}");
        }
    }

    #[test]
    fn origins_keep_scheme_address_and_port() {
        assert_eq!(
            canonical_resource_origin("HTTP://[::1]/a").as_deref(),
            Some("http://[::1]:80/")
        );
        assert_eq!(canonical_resource_origin("http://localhost/a"), None);
        assert_eq!(
            canonical_resource_origin("http://127.0.0.1/a?redirect=x"),
            None
        );
    }
}
