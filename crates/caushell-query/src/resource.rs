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

/// A named locator is usable only with a live host-maintained route binding.
pub fn canonical_resource_named_endpoint(value: &str) -> Option<String> {
    let (scheme, rest) = value.split_once("://")?;
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(h, p)| (h, Some(p)));
    if host.len() > 253
        || !host.bytes().any(|b| b.is_ascii_alphabetic())
        || host.split('.').all(|label| {
            label.bytes().all(|b| b.is_ascii_digit())
                || label
                    .strip_prefix("0x")
                    .or_else(|| label.strip_prefix("0X"))
                    .is_some_and(|digits| {
                        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_hexdigit())
                    })
        })
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return None;
    }
    let numeric = format!(
        "{scheme}://127.0.0.1{}/{path}",
        port.map_or(String::new(), |p| format!(":{p}"))
    );
    let normalized = canonical_resource_endpoint(&numeric)?;
    let (scheme, rest) = normalized.split_once("://")?;
    let suffix = rest.strip_prefix("127.0.0.1")?;
    Some(format!("{scheme}://{}{suffix}", host.to_ascii_lowercase()))
}

pub fn canonical_resource_named_origin(value: &str) -> Option<String> {
    let endpoint = canonical_resource_named_endpoint(value)?;
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

    #[test]
    fn named_locators_are_canonical_but_never_numeric_resource_facts() {
        for (value, expected) in [
            ("HTTPS://Reports.Example/a", "https://reports.example:443/a"),
            ("http://localhost:8080/", "http://localhost:8080/"),
            (
                "https://service-1.internal/x",
                "https://service-1.internal:443/x",
            ),
        ] {
            assert_eq!(
                canonical_resource_named_endpoint(value).as_deref(),
                Some(expected)
            );
            assert!(canonical_resource_endpoint(value).is_none());
        }
        for value in [
            "http://127.0.0.1/a",
            "http://0x7f000001/a",
            "http://0X7F.0.0.1/a",
            "http://[::1]/a",
            "http://local..test/a",
            "http://-local.test/a",
            "http://local-.test/a",
            "http://localhost./a",
            "http://local_host/a",
            "http://user@localhost/a",
            "http://localhost:0/a",
            "http://localhost/a%2fb",
            "http://localhost/a/../b",
            "http://localhost/a?x=1",
            "http://localhost\\evil/a",
            "http://éxample.test/a",
            "ftp://localhost/a",
        ] {
            assert!(
                canonical_resource_named_endpoint(value).is_none(),
                "{value}"
            );
        }
    }
}
