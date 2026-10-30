//! A fact transport used only by the owning Bash collector, never an analyzer.
use serde_json::{Value, json};
use std::{
    io::{self, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};
pub fn submit(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() != 4 {
        return Err("frame-submit requires endpoint, ticket, nonce and cwd".into());
    }
    let address = args[0]
        .strip_prefix("http://")
        .ok_or("private HTTP endpoint required")?;
    let (host, path) = address.split_once('/').ok_or("endpoint path missing")?;
    if !host.contains(':') || host.contains(['\r', '\n', '@']) || path.contains(['\r', '\n']) {
        return Err("invalid private endpoint".into());
    }
    let raw = io::stdin()
        .lock()
        .take(65537)
        .bytes()
        .collect::<Result<Vec<_>, _>>()?;
    if raw.len() > 65536 {
        return Err("frame capture exceeds byte budget".into());
    }
    let body =
        serde_json::to_vec(&json!({"ticket":args[1],"nonce":args[2],"cwd":args[3],"raw":raw}))?;
    let endpoint = host
        .to_socket_addrs()?
        .next()
        .ok_or("controller endpoint unavailable")?;
    let mut stream = TcpStream::connect_timeout(&endpoint, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(Duration::from_secs(20)))?;
    write!(
        stream,
        "POST /{path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    stream.flush()?;
    let mut packet = Vec::new();
    stream.take(1048577).read_to_end(&mut packet)?;
    if packet.len() > 1048576 {
        return Err("controller response exceeds budget".into());
    }
    let split = packet
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("controller response is incomplete")?;
    let header = std::str::from_utf8(&packet[..split])?;
    if !header.starts_with("HTTP/1.0 200 ") && !header.starts_with("HTTP/1.1 200 ") {
        return Err("owning-frame controller rejected transport".into());
    }
    let response: Value = serde_json::from_slice(&packet[split + 4..])?;
    if response["ticket"] != args[1] || response["protocol"] != 1 {
        return Err("cross-action frame response".into());
    }
    if response["allowed"] != true {
        return Err(response["reason"]
            .as_str()
            .unwrap_or("Caushell did not authorize this action")
            .to_owned()
            .into());
    }
    Ok(())
}
