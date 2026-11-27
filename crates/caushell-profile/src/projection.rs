use caushell_parse::{CommandFact, CommandTokenKind, SourceSpan};

use std::borrow::Cow;

use crate::{FlagName, InvocationShape, OptionPrefixPolicy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvocationRuntimeContext {
    pub shell_kind: caushell_types::ShellKind,
    pub stdin_payload_available: bool,
    pub interactive_session: bool,
}

impl Default for InvocationRuntimeContext {
    fn default() -> Self {
        Self {
            shell_kind: caushell_types::ShellKind::Bash,
            stdin_payload_available: false,
            interactive_session: false,
        }
    }
}

impl InvocationRuntimeContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_shell_kind(mut self, kind: caushell_types::ShellKind) -> Self {
        self.shell_kind = kind;
        self
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

/// A proof issued against a particular original shell word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubstitutionOutputProof {
    ScalarShape(crate::StdoutScalarShape),
    /// Plain pidof output contains decimal process IDs and separators only.
    /// An unquoted capture can still expand into zero or several fields.
    DecimalPidFields,
    ArithmeticField { prefix: String, suffix: String },
    /// One quoted pathname word surrounding a verified calendar capture.
    CalendarFilename { prefix: String, suffix: String },
    /// One quoted word whose complete pathname spelling is bounded, including
    /// the case where its command substitution emits nothing.
    PathWord(caushell_types::RuntimeArgumentDomain),
    /// A calendar capture and its literal affixes are local filename fields
    /// under all IFS settings. Their count and actual bytes remain unknown.
    LocalFilenameFields,
    /// Fields of one unquoted calendar pathname with a literal directory
    /// prefix and extension. All nonempty fields name working-directory
    /// descendants, but splitting can shift earlier fields into source roles.
    LocalMovePathFields,
    /// An unquoted date capture whose stdout is empty or decimal digits.
    /// Field splitting may still remove it or produce more than one field.
    DecimalCalendarFields,
    /// An unsigned line count followed by a literal q. Splitting may
    /// still produce empty fields and additional input operands.
    LineCountQuit,
    /// Exact literal segments around one or two quoted day-of-month results.
    SedDayTemplate { literal_parts: Vec<String> },
    /// One quoted capture whose records contain only nonempty decimal fields.
    /// Empty capture and multiple newline-separated records remain possible.
    SedDecimalAddresses { suffix: String, max_records: Option<u64> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedArg {
    pub word_context: crate::WordContext,
    pub text: String,
    pub implicit_input_source: Option<caushell_types::ImplicitInputSource>,
    pub runtime_argument_domain: Option<caushell_types::RuntimeArgumentDomain>,
    pub runtime_data: bool,
    /// A proven output shape for a whole quoted scalar substitution. Original
    /// source bytes and dynamic path resolution remain unchanged.
    pub substitution_shape: Option<crate::StdoutScalarShape>,
    /// Positive lexical spelling bound for every field of a shell expansion.
    /// Not an exact value or a filesystem containment/provenance assertion.
    pub lexical_field_prefix: Option<String>,
    /// A post-expansion layout bound usable only inside a modeled native
    /// dispatch region. It does not make this word an exact argv operand.
    pub native_region_field: Option<crate::OptionalBashField>,
    pub kind: ProjectedArgKind,
    pub quoted: bool,
    pub node_kind: String,
    pub span: SourceSpan,
}

impl ProjectedArg {
    pub fn substitution_output_proof(&self) -> Option<SubstitutionOutputProof> {
        if self.implicit_input_source == Some(caushell_types::ImplicitInputSource::CommandSubstitution)
            && let Some(caushell_types::RuntimeArgumentDomain::ArithmeticTemplate { prefix, suffix }) =
                &self.runtime_argument_domain
        {
            return Some(SubstitutionOutputProof::ArithmeticField {
                prefix: prefix.clone(),
                suffix: suffix.clone(),
            });
        }
        self.substitution_shape.map(SubstitutionOutputProof::ScalarShape)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedInvocation {
    pub shell_kind: caushell_types::ShellKind,
    /// The selected tool's CLI grammar, not shell lexical state.
    pub option_prefixes: OptionPrefixPolicy,
    pub command_name: Option<String>,
    pub args: Vec<ProjectedArg>,
    pub stdin_payload_available: bool,
    pub interactive_session: bool,
}

impl ProjectedInvocation {
    /// Borrow the unchanged legacy projection. Only opted-in CLI grammars may
    /// reinterpret plus tokens or the plus option terminator, after argv has
    /// been materialized. Text, spans and runtime-data provenance stay intact.
    pub(crate) fn with_option_prefixes(&self, policy: OptionPrefixPolicy) -> Cow<'_, Self> {
        if policy == OptionPrefixPolicy::DashOnly {
            return Cow::Borrowed(self);
        }
        let mut terminated = false;
        let differs = self.args.iter().any(|arg| {
            let kind = prefixed_arg_kind(arg, policy, &mut terminated);
            kind != arg.kind
        });
        if !differs && self.option_prefixes == policy {
            return Cow::Borrowed(self);
        }
        let mut projection = self.clone();
        projection.apply_option_prefixes(policy);
        Cow::Owned(projection)
    }

    pub(crate) fn apply_option_prefixes(&mut self, policy: OptionPrefixPolicy) {
        self.option_prefixes = policy;
        if policy == OptionPrefixPolicy::DashOnly {
            return;
        }
        let mut terminated = false;
        for arg in &mut self.args {
            arg.kind = prefixed_arg_kind(arg, policy, &mut terminated);
        }
    }

    pub fn shape(&self) -> InvocationShape {
        let mut shape = InvocationShape::new();
        shape.exact_positional_count = Some(0);
        let mut before_dashdash = true;

        for (index, arg) in self.args.iter().enumerate() {
            let template = arg.runtime_argument_domain.as_ref()
                .is_some_and(caushell_types::RuntimeArgumentDomain::is_spelling_template)
            .then(|| crate::argument_structure(arg));
            if let Some(structure) = &template {
                shape.argument_templates.insert(index, structure.clone());
            }
            match arg.kind {
                ProjectedArgKind::Flag => {
                    shape.flags.push(FlagName::new(arg.text.clone()));
                }
                ProjectedArgKind::Positional => {
                    shape.observe_positional_width(arg);
                    if let Some(structure) = template {
                        shape
                            .positional_templates
                            .insert(shape.positional_args.len(), structure);
                    }
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

fn prefixed_arg_kind(
    arg: &ProjectedArg,
    policy: OptionPrefixPolicy,
    terminated: &mut bool,
) -> ProjectedArgKind {
    if *terminated {
        return ProjectedArgKind::Positional;
    }
    if policy.is_terminator(&arg.text) {
        *terminated = true;
        return ProjectedArgKind::DashDash;
    }
    if arg.text.len() > 1 && arg.text.starts_with('+') {
        return ProjectedArgKind::Flag;
    }
    arg.kind
}

pub fn project_invocation(
    command: &CommandFact,
    context: InvocationRuntimeContext,
) -> ProjectedInvocation {
    let args = command
        .tokens
        .iter()
        .map(|token| ProjectedArg {
            word_context: crate::WordContext::ShellArgument,
            text: token.text.clone(),
            implicit_input_source: token.implicit_input_source,
            runtime_argument_domain: token.runtime_argument_domain.clone(),
            runtime_data: token.runtime_data,
            substitution_shape: None,
            native_region_field: None,
            lexical_field_prefix: None,
            kind: project_arg_kind(&token.kind),
            quoted: token.quoted,
            node_kind: token.node_kind.clone(),
            span: token.span.clone(),
        })
        .collect();

    ProjectedInvocation {
        shell_kind: context.shell_kind,
        option_prefixes: OptionPrefixPolicy::DashOnly,
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
        assert_eq!(modifier_ids, vec!["command_string_mode", "rcfile"]);
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
