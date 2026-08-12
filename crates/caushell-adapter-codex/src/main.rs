use std::env;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use caushell_adapter_codex::{
    AdapterError, CodexNeedApprovalMode, run_permission_request, run_pretooluse,
};

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
    let options = parse_options(args)?;
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    run_pretooluse(
        &options.socket_path,
        options.need_approval_mode,
        stdin.lock(),
        &mut stdout,
    )
}

fn run_permission_request_command(args: impl Iterator<Item = String>) -> Result<(), AdapterError> {
    let options = parse_options(args)?;
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    run_permission_request(
        &options.socket_path,
        options.need_approval_mode,
        stdin.lock(),
        &mut stdout,
    )
}

struct AdapterOptions {
    socket_path: PathBuf,
    need_approval_mode: CodexNeedApprovalMode,
}

fn parse_options(mut args: impl Iterator<Item = String>) -> Result<AdapterOptions, AdapterError> {
    let mut socket_path = None;
    let mut need_approval_mode = CodexNeedApprovalMode::Block;

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
            "--need-approval-mode" => {
                let Some(value) = args.next() else {
                    return Err(AdapterError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--need-approval-mode requires a following value",
                    )));
                };
                need_approval_mode = parse_need_approval_mode(&value)?;
            }
            other => {
                return Err(AdapterError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unexpected caushell-adapter-codex argument: {other}"),
                )));
            }
        }
    }

    let socket_path = socket_path.ok_or_else(|| {
        AdapterError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--socket is required for caushell-adapter-codex",
        ))
    })?;

    Ok(AdapterOptions {
        socket_path,
        need_approval_mode,
    })
}

fn parse_need_approval_mode(value: &str) -> Result<CodexNeedApprovalMode, AdapterError> {
    match value {
        "block" => Ok(CodexNeedApprovalMode::Block),
        "observe" => Ok(CodexNeedApprovalMode::Observe),
        other => Err(AdapterError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid --need-approval-mode {other:?}; expected block or observe"),
        ))),
    }
}

fn print_usage() {
    eprintln!(
        "usage:\n  caushell-adapter-codex pretooluse --socket <path> [--need-approval-mode <block|observe>]\n  caushell-adapter-codex permission-request --socket <path> [--need-approval-mode <block|observe>]\n\npretooluse reads Codex PreToolUse hook JSON from stdin and writes Codex hook decision JSON to stdout\npermission-request reads Codex PermissionRequest hook JSON from stdin and writes Codex hook decision JSON to stdout"
    );
}
