use std::env;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use caushell_adapter_codex::{AdapterError, run_permission_request, run_pretooluse};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), AdapterError> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        return Ok(());
    };

    match command.as_str() {
        "pretooluse" => run_pretooluse_command(args),
        "permission-request" => run_permission_request_command(args),
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        other => {
            eprintln!("unknown caushell-adapter-codex command: {other}");
            print_usage();
            Ok(())
        }
    }
}

fn run_pretooluse_command(args: impl Iterator<Item = String>) -> Result<(), AdapterError> {
    let socket_path = parse_socket_path(args)?;
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    run_pretooluse(&socket_path, stdin.lock(), &mut stdout)
}

fn run_permission_request_command(args: impl Iterator<Item = String>) -> Result<(), AdapterError> {
    let socket_path = parse_socket_path(args)?;
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    run_permission_request(&socket_path, stdin.lock(), &mut stdout)
}

fn parse_socket_path(mut args: impl Iterator<Item = String>) -> Result<PathBuf, AdapterError> {
    let mut socket_path = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => {
                let Some(path) = args.next() else {
                    return Err(AdapterError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--socket requires a following path",
                    )));
                };

                socket_path = Some(PathBuf::from(path));
            }
            other => {
                return Err(AdapterError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unexpected caushell-adapter-codex argument: {other}"),
                )));
            }
        }
    }

    socket_path.ok_or_else(|| {
        AdapterError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--socket is required for caushell-adapter-codex",
        ))
    })
}

fn print_usage() {
    eprintln!(
        "usage:\n  caushell-adapter-codex pretooluse --socket <path>\n  caushell-adapter-codex permission-request --socket <path>\n\npretooluse reads Codex PreToolUse hook JSON from stdin and writes Codex hook decision JSON to stdout\npermission-request reads Codex PermissionRequest hook JSON from stdin and writes Codex hook decision JSON to stdout"
    );
}
