//! Executor-side observation bridge. No Docker/task policy in the analysis core.
use caushell_core::LocalFilesystem;
use caushell_runner::{DirectoryRead, FileContentRead, FilesystemView, MAX_FILE_CONTENT_BYTES};
use caushell_types::*;
use serde_json::{Value, json};
#[cfg(unix)]
use std::os::{fd::FromRawFd, unix::net::UnixStream};
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    path::Path,
    sync::{Arc, Mutex},
};
const MAX_WIRE: usize = 2 * 1024 * 1024;

fn packet(reader: &mut impl BufRead) -> io::Result<Value> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_WIRE + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "closed observation channel",
        ));
    }
    if bytes.is_empty() || bytes.len() > MAX_WIRE || bytes.last() != Some(&b'\n') {
        return Err(io::Error::other(
            "incomplete or oversized private observation packet",
        ));
    }
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}
fn send(writer: &mut impl Write, v: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, v)?;
    writer.write_all(b"\n")?;
    writer.flush()
}
fn failed(path: &str, limit: usize, detail: &str) -> FileContentRead {
    FileContentRead::failed(
        FileContentSource::Unavailable,
        path,
        limit,
        FileContentStatus::Unavailable,
        detail,
    )
}

#[cfg(unix)]
struct Remote {
    channel: Mutex<(BufReader<UnixStream>, UnixStream, u64)>,
}
#[cfg(unix)]
impl Remote {
    fn call(&self, op: &str, path: &str, limit: Value) -> Option<Value> {
        let mut c = self.channel.lock().ok()?;
        c.2 += 1;
        let id = c.2;
        let request = json!({"id":id,"op":op,"path":path,"limit":limit});
        send(&mut c.1, &request).ok()?;
        let r = packet(&mut c.0).ok()?;
        if r.get("request")? != &request || r.get("error").is_some() {
            return None;
        }
        r.get("value").cloned()
    }
}
#[cfg(unix)]
impl FilesystemView for Remote {
    fn source(&self) -> FilesystemObservationSource {
        FilesystemObservationSource::SuppliedView
    }
    fn execution_account(&self) -> Option<RuntimeAccount> {
        serde_json::from_value(self.call("account", "", Value::Null)?).ok()
    }
    fn entry(&self, path: &str) -> FilesystemEntry {
        self.call("entry", path, Value::Null)
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_else(|| FilesystemEntry::Unavailable {
                reason: "execution-namespace observation unavailable".into(),
            })
    }
    fn read_file(&self, path: &str, limit: usize) -> FileContentRead {
        if limit > MAX_FILE_CONTENT_BYTES {
            return failed(path, limit, "file budget is invalid");
        }
        let Some(v) = self.call("file", path, json!(limit)) else {
            return failed(path, limit, "private file channel failed");
        };
        let parsed = (|| {
            let o: FileContentObservation =
                serde_json::from_value(v.get("observation")?.clone()).ok()?;
            if o.path != path || o.byte_limit != limit {
                return None;
            }
            if o.status != FileContentStatus::Complete {
                return Some(FileContentRead::failed(
                    FileContentSource::SuppliedView,
                    path,
                    limit,
                    o.status,
                    o.detail.unwrap_or_default(),
                ));
            }
            let data: Vec<u8> = serde_json::from_value(v.get("bytes")?.clone()).ok()?;
            let r = FileContentRead::complete(
                FileContentSource::SuppliedView,
                path,
                limit,
                o.identity.clone(),
                data,
            );
            if r.observation.sha256 != o.sha256 || r.observation.bytes_observed != o.bytes_observed
            {
                return None;
            }
            Some(r)
        })();
        parsed.unwrap_or_else(|| failed(path, limit, "invalid supplied file observation"))
    }
    fn read_directory(&self, path: &str, limits: DirectoryReadLimits) -> DirectoryRead {
        let fail = || {
            DirectoryRead::failed(
                self.source(),
                path,
                limits,
                DirectoryReadStatus::Unavailable,
                "invalid or unavailable directory channel",
            )
        };
        let Some(v) = self.call("directory", path, serde_json::to_value(limits).unwrap()) else {
            return fail();
        };
        let parsed = (|| {
            let o: DirectoryObservation =
                serde_json::from_value(v.get("observation")?.clone()).ok()?;
            if o.path != path || o.limits != limits {
                return None;
            }
            if o.status != DirectoryReadStatus::Complete {
                return Some(DirectoryRead::failed(
                    self.source(),
                    path,
                    limits,
                    o.status,
                    o.detail.unwrap_or_default(),
                ));
            }
            let entries: Vec<DirectoryEntry> =
                serde_json::from_value(v.get("entries")?.clone()).ok()?;
            let r = DirectoryRead::complete(self.source(), path, limits, o.identity?, entries);
            if r.observation.sha256 != o.sha256
                || r.observation.entries_observed != o.entries_observed
            {
                return None;
            }
            Some(r)
        })();
        parsed.unwrap_or_else(fail)
    }
    fn runtime_file(&self, path: &str) -> RuntimeFileObservation {
        self.call("runtime_file", path, Value::Null)
            .and_then(|v| serde_json::from_value(v).ok())
            .filter(|v: &RuntimeFileObservation| v.content.path == path)
            .unwrap_or_else(|| RuntimeFileObservation {
                content: failed(
                    path,
                    caushell_runner::MAX_RUNTIME_FILE_BYTES,
                    "runtime channel unavailable",
                )
                .observation,
                executable: None,
            })
    }
}

fn observe() -> io::Result<()> {
    // Only the observer is hardened. The task's identity, privileges and environment
    // are unchanged. Without this protection a same-UID tool could forge the pipe.
    #[cfg(target_os = "linux")]
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    let mut initial = io::stdout().lock();
    send(
        &mut initial,
        &json!({"observer_protocol":1,"pid":std::process::id(),"protected":cfg!(target_os="linux")}),
    )?;
    drop(initial);
    let view = LocalFilesystem;
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let request = match packet(&mut input) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };
        let value = (|| -> Result<Value, String> {
            let obj = request.as_object().ok_or("expected object")?;
            if obj.len() != 4 || !request["id"].is_u64() {
                return Err("invalid request identity".into());
            }
            let op = request["op"]
                .as_str()
                .ok_or("missing observation operation")?;
            let path = request["path"].as_str().ok_or("missing observation path")?;
            if op != "account"
                && (!path.starts_with('/') || path.len() > 16384 || path.contains('\0'))
            {
                return Err("invalid observation path".into());
            }
            match op {
                "account" => Ok(serde_json::to_value(view.execution_account()).unwrap()),
                "entry" => Ok(serde_json::to_value(view.entry(path)).unwrap()),
                "runtime_file" => Ok(serde_json::to_value(view.runtime_file(path)).unwrap()),
                "file" => {
                    let limit = request["limit"]
                        .as_u64()
                        .filter(|n| *n <= MAX_FILE_CONTENT_BYTES as u64)
                        .ok_or("invalid file budget")? as usize;
                    let r = view.read_file(path, limit);
                    Ok(json!({"observation":r.observation,"bytes":r.complete_bytes(path,limit)}))
                }
                "directory" => {
                    let limits: DirectoryReadLimits =
                        serde_json::from_value(request["limit"].clone())
                            .map_err(|e| e.to_string())?;
                    if !limits.is_valid() {
                        return Err("invalid directory budget".into());
                    }
                    let r = view.read_directory(path, limits);
                    Ok(
                        json!({"observation":r.observation,"entries":r.complete_entries(path,limits)}),
                    )
                }
                _ => Err("unknown read-only observation operation".into()),
            }
        })();
        let response = match value {
            Ok(value) => json!({"request":request,"value":value}),
            Err(error) => json!({"request":request,"error":error}),
        };
        send(&mut output, &response)?;
    }
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args == ["observe"] {
        observe()?;
        return Ok(());
    }
    #[cfg(unix)]
    {
        if args.len() != 4 || args[0] != "serve" {
            return Err("usage: trusted-filesystem-host observe | serve FD CONFIG STORE".into());
        }
        let fd: i32 = args[1].parse()?;
        if fd < 3 {
            return Err("private observation FD must not be stdio".into());
        }
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;
        let view = Remote {
            channel: Mutex::new((BufReader::new(stream.try_clone()?), stream, 0)),
        };
        if view.execution_account().is_none() {
            return Err("execution account observation unavailable".into());
        }
        let mut runtime = caushell::CliRuntime::new_with_filesystem_view(
            Some(Path::new(&args[2])),
            Some(Path::new(&args[3])),
            Arc::new(view),
        )?;
        caushell::serve_stdio(&mut runtime, io::stdin().lock(), &mut io::stdout().lock())?;
        return Ok(());
    }
    #[cfg(not(unix))]
    Err("Unix private descriptors required".into())
}
