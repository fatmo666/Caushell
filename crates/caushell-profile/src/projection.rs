use caushell_parse::{CommandFact, CommandTokenKind, SourceSpan};

use crate::{FlagName, InvocationShape};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InvocationRuntimeContext {
    pub stdin_payload_available: bool,
    pub interactive_session: bool,
}

impl InvocationRuntimeContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_stdin_payload_available(mut self) -> Self {
        self.stdin_payload_available = true;
        self
    }

    pub fn with_interactive_session(mut self) -> Self {
        self.interactive_session = true;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectedArgKind {
    Flag,
    Positional,
    DashDash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedArg {
    pub text: String,
    pub kind: ProjectedArgKind,
    pub quoted: bool,
    pub node_kind: String,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedInvocation {
    pub command_name: Option<String>,
    pub args: Vec<ProjectedArg>,
    pub stdin_payload_available: bool,
    pub interactive_session: bool,
}

impl ProjectedInvocation {
    pub fn shape(&self) -> InvocationShape {
        let mut shape = InvocationShape::new();
        let mut before_dashdash = true;

        for arg in &self.args {
            match arg.kind {
                ProjectedArgKind::Flag => {
                    shape.flags.push(FlagName::new(arg.text.clone()));
                }
                ProjectedArgKind::Positional => {
                    shape.positional_args.push(arg.text.clone());
                    if before_dashdash {
                        shape.positional_args_before_dashdash.push(arg.text.clone());
                    }
                }
                ProjectedArgKind::DashDash => {
                    shape.has_dashdash = true;
                    before_dashdash = false;
                }
            }
        }

        shape.stdin_payload_available = self.stdin_payload_available;
        shape.interactive_session = self.interactive_session;
        shape
    }
}

pub fn project_invocation(
    command: &CommandFact,
    context: InvocationRuntimeContext,
) -> ProjectedInvocation {
    let args = command
        .tokens
        .iter()
        .map(|token| ProjectedArg {
            text: token.text.clone(),
            kind: project_arg_kind(&token.kind),
            quoted: token.quoted,
            node_kind: token.node_kind.clone(),
            span: token.span.clone(),
        })
        .collect();

    ProjectedInvocation {
        command_name: command.command_name.clone(),
        args,
        stdin_payload_available: context.stdin_payload_available,
        interactive_session: context.interactive_session,
    }
}

fn project_arg_kind(kind: &CommandTokenKind) -> ProjectedArgKind {
    match kind {
        CommandTokenKind::Flag => ProjectedArgKind::Flag,
        CommandTokenKind::Arg => ProjectedArgKind::Positional,
        CommandTokenKind::DashDash => ProjectedArgKind::DashDash,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use caushell_parse::parse_command;
    use caushell_types::ShellKind;

    use super::{InvocationRuntimeContext, ProjectedArgKind, project_invocation};
    use crate::{
        BindError, CommandProfile, load_command_profile_from_path, select_form, select_invocation,
    };

    fn built_in_profile(name: &str) -> CommandProfile {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join(format!("{name}.yaml"));

        load_command_profile_from_path(&profile_path).expect("expected built-in profile to load")
    }

    #[test]
    fn project_invocation_preserves_order_and_metadata() {
        let artifact = parse_command(
            r#"bash --rcfile ./team.rc -c 'echo ok' runner a b"#,
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(
            command,
            InvocationRuntimeContext::new().with_interactive_session(),
        );

        let texts: Vec<&str> = projection
            .args
            .iter()
            .map(|arg| arg.text.as_str())
            .collect();
        let kinds: Vec<ProjectedArgKind> = projection.args.iter().map(|arg| arg.kind).collect();

        assert_eq!(projection.command_name.as_deref(), Some("bash"));
        assert_eq!(
            texts,
            vec!["--rcfile", "./team.rc", "-c", "echo ok", "runner", "a", "b"]
        );
        assert_eq!(
            kinds,
            vec![
                ProjectedArgKind::Flag,
                ProjectedArgKind::Positional,
                ProjectedArgKind::Flag,
                ProjectedArgKind::Positional,
                ProjectedArgKind::Positional,
                ProjectedArgKind::Positional,
                ProjectedArgKind::Positional,
            ]
        );
        assert!(projection.args[3].quoted);
        assert!(projection.interactive_session);
    }

    #[test]
    fn project_invocation_preserves_dashdash_marker() {
        let artifact = parse_command(r#"echo hello -- -n"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());

        let texts: Vec<&str> = projection
            .args
            .iter()
            .map(|arg| arg.text.as_str())
            .collect();
        let kinds: Vec<ProjectedArgKind> = projection.args.iter().map(|arg| arg.kind).collect();

        assert_eq!(texts, vec!["hello", "--", "-n"]);
        assert_eq!(
            kinds,
            vec![
                ProjectedArgKind::Positional,
                ProjectedArgKind::DashDash,
                ProjectedArgKind::Positional,
            ]
        );

        let shape = projection.shape();
        assert_eq!(
            shape.positional_args,
            vec!["hello".to_string(), "-n".to_string()]
        );
        assert_eq!(
            shape.positional_args_before_dashdash,
            vec!["hello".to_string()]
        );
        assert!(shape.has_dashdash);
    }

    #[test]
    fn projected_invocation_shape_collects_flags_and_positionals() {
        let artifact = parse_command(
            r#"bash --rcfile ./team.rc -c 'echo ok' runner a b"#,
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let shape = projection.shape();

        let flags: Vec<&str> = shape.flags.iter().map(|flag| flag.as_str()).collect();
        assert_eq!(flags, vec!["--rcfile", "-c"]);
        assert_eq!(
            shape.positional_args,
            vec![
                "./team.rc".to_string(),
                "echo ok".to_string(),
                "runner".to_string(),
                "a".to_string(),
                "b".to_string(),
            ]
        );
    }

    #[test]
    fn projection_plus_binding_selects_bash_command_string_and_modifier() {
        let profile = built_in_profile("bash");
        let artifact = parse_command(r#"bash --rcfile ./team.rc -c 'echo ok'"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");

        let modifier_ids: Vec<&str> = selection
            .modifiers
            .iter()
            .map(|modifier| modifier.id.as_str())
            .collect();

        assert_eq!(selection.form.id.as_str(), "command_string");
        assert_eq!(modifier_ids, vec!["rcfile"]);
    }

    #[test]
    fn projection_plus_binding_selects_bash_script_file() {
        let profile = built_in_profile("bash");
        let artifact = parse_command(r#"bash ./scripts/build.sh --release"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let shape = projection.shape();
        let form = select_form(&profile, &shape).expect("expected script_file form");

        assert_eq!(form.id.as_str(), "script_file");
    }

    #[test]
    fn projection_plus_runtime_context_selects_bash_implicit_stdin() {
        let profile = built_in_profile("bash");
        let artifact = parse_command("bash", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(
            command,
            InvocationRuntimeContext::new().with_stdin_payload_available(),
        );
        let shape = projection.shape();
        let form = select_form(&profile, &shape).expect("expected stdin_script_implicit form");

        assert_eq!(form.id.as_str(), "stdin_script_implicit");
    }

    #[test]
    fn projection_plus_runtime_context_selects_bash_interactive() {
        let profile = built_in_profile("bash");
        let artifact = parse_command("bash", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(
            command,
            InvocationRuntimeContext::new().with_interactive_session(),
        );
        let shape = projection.shape();
        let form = select_form(&profile, &shape).expect("expected interactive form");

        assert_eq!(form.id.as_str(), "interactive");
    }

    #[test]
    fn conflicting_runtime_context_is_ambiguous() {
        let profile = built_in_profile("bash");
        let artifact = parse_command("bash", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(
            command,
            InvocationRuntimeContext::new()
                .with_stdin_payload_available()
                .with_interactive_session(),
        );
        let shape = projection.shape();

        let error = select_form(&profile, &shape).expect_err("expected ambiguous match");

        match error {
            BindError::MultipleFormsMatched {
                command_name,
                form_ids,
            } => {
                assert_eq!(command_name, "bash");
                assert_eq!(
                    form_ids,
                    vec![
                        "stdin_script_implicit".to_string(),
                        "interactive".to_string(),
                    ]
                );
            }
            other => panic!("unexpected bind error: {other:?}"),
        }
    }
}
