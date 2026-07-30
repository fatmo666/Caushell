use std::fs;
use std::path::Path;

use crate::{CommandProfile, NormalizeError, RawCommandProfile, normalize_command_profile};

#[derive(Debug)]
pub enum LoadProfileError {
    Read(std::io::Error),
    ParseYaml(serde_yaml::Error),
    Normalize(NormalizeError),
}

impl std::fmt::Display for LoadProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(error) => write!(f, "failed to read profile file: {error}"),
            Self::ParseYaml(error) => write!(f, "failed to parse profile YAML: {error}"),
            Self::Normalize(error) => write!(f, "failed to normalize profile: {error:?}"),
        }
    }
}

impl std::error::Error for LoadProfileError {}

pub fn load_raw_command_profile_from_str(
    input: &str,
) -> Result<RawCommandProfile, LoadProfileError> {
    serde_yaml::from_str(input).map_err(LoadProfileError::ParseYaml)
}

pub fn load_command_profile_from_str(input: &str) -> Result<CommandProfile, LoadProfileError> {
    let raw = load_raw_command_profile_from_str(input)?;
    normalize_command_profile(raw).map_err(LoadProfileError::Normalize)
}

pub fn load_raw_command_profile_from_path(
    path: impl AsRef<Path>,
) -> Result<RawCommandProfile, LoadProfileError> {
    let content = fs::read_to_string(path).map_err(LoadProfileError::Read)?;
    load_raw_command_profile_from_str(&content)
}

pub fn load_command_profile_from_path(
    path: impl AsRef<Path>,
) -> Result<CommandProfile, LoadProfileError> {
    let content = fs::read_to_string(path).map_err(LoadProfileError::Read)?;
    load_command_profile_from_str(&content)
}

#[cfg(test)]
mod tests {
    use super::{
        LoadProfileError, load_command_profile_from_path, load_command_profile_from_str,
        load_raw_command_profile_from_str,
    };
    use crate::{
        BindingSpec, EffectKind, EffectTarget, PathPurpose, PathRole, SelectorExpr,
        SelectorPredicate, SemanticType, ValueMatcher,
    };
    use std::path::PathBuf;

    #[test]
    fn load_raw_command_profile_from_str_parses_yaml() {
        let input = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity:
  canonical_name: bash
  aliases:
    - sh-compatible
trust:
  tier: tier_a
  source: built_in
forms:
  - id: command_string
    selector:
      kind: has_flag
      flag: "-c"
    parameters:
      - name: payload
        semantic:
          kind: payload
          language: bash
          source: inline_string
          recursive: true
        binding:
          kind: following_flag
          flag: "-c"
          operand_mode: next_positional_after_dashdash
modifiers:
  - id: rcfile
    matcher:
      kind: any_flag
      flags:
        - "--rcfile"
    parameters:
      - name: startup_config
        semantic:
          kind: path
          role: config
          purpose: startup_config
        binding:
          kind: following_matched_flag
          operand_mode: next_arg
    effects:
      - kind: load_config
        target:
          kind: slot
          name: startup_config
extensions: {}
"#;

        let raw =
            load_raw_command_profile_from_str(input).expect("expected raw YAML profile to parse");

        assert_eq!(raw.identity.canonical_name, "bash");
        assert_eq!(raw.identity.aliases, vec!["sh-compatible"]);
        assert_eq!(raw.forms.len(), 1);
        assert_eq!(raw.modifiers.len(), 1);
    }

    #[test]
    fn load_command_profile_from_str_normalizes_profile() {
        let input = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity:
  canonical_name: bash
trust:
  tier: tier_a
  source: built_in
forms:
  - id: command_string
    selector:
      kind: has_flag
      flag: "-c"
    parameters:
      - name: payload
        semantic:
          kind: payload
          language: bash
          source: inline_string
          recursive: true
        binding:
          kind: following_flag
          flag: "-c"
          operand_mode: next_positional_after_dashdash
modifiers:
  - id: rcfile
    matcher:
      kind: any_flag
      flags:
        - "--rcfile"
    parameters:
      - name: startup_config
        semantic:
          kind: path
          role: config
          purpose: startup_config
        binding:
          kind: following_matched_flag
          operand_mode: next_arg
    effects:
      - kind: load_config
        target:
          kind: slot
          name: startup_config
extensions: {}
"#;

        let profile = load_command_profile_from_str(input).expect("expected normalized profile");

        assert_eq!(profile.primary_name(), "bash");
        assert_eq!(profile.forms.len(), 1);
        assert_eq!(profile.modifiers.len(), 1);

        match &profile.forms[0].selector {
            SelectorExpr::Predicate(SelectorPredicate::HasFlag(flag_name)) => {
                assert_eq!(flag_name.as_str(), "-c")
            }
            other => panic!("unexpected selector predicate: {other:?}"),
        }

        match &profile.modifiers[0].parameters[0].semantic {
            SemanticType::Path(semantic) => {
                assert_eq!(semantic.role, PathRole::Config);
                assert_eq!(semantic.purpose, Some(PathPurpose::StartupConfig));
            }
            other => panic!("unexpected modifier semantic: {other:?}"),
        }

        assert_eq!(
            profile.forms[0].parameters[0].binding,
            BindingSpec::FollowingFlag {
                flag_name: crate::FlagName::new("-c"),
                operand_mode: crate::FlagOperandMode::NextPositionalAfterDashDash,
            }
        );
        assert_eq!(
            profile.modifiers[0].parameters[0].binding,
            BindingSpec::FollowingMatchedFlag {
                operand_mode: crate::FlagOperandMode::NextArg,
            }
        );

        assert_eq!(profile.modifiers[0].effects[0].kind, EffectKind::LoadConfig);
        assert_eq!(
            profile.modifiers[0].effects[0].target,
            EffectTarget::Slot(crate::SlotName::new("startup_config"))
        );
    }

    #[test]
    fn load_command_profile_from_str_parses_has_flag_at_least_selector() {
        let input = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity:
  canonical_name: mkfs
trust:
  tier: tier_a
  source: built_in
forms:
  - id: dry_run
    selector:
      kind: has_flag_at_least
      flag: "-V"
      count: 2
modifiers: []
extensions: {}
"#;

        let profile = load_command_profile_from_str(input).expect("expected normalized profile");

        match &profile.forms[0].selector {
            SelectorExpr::Predicate(SelectorPredicate::HasFlagAtLeast(flag_name, count)) => {
                assert_eq!(flag_name.as_str(), "-V");
                assert_eq!(*count, 2);
            }
            other => panic!("unexpected selector predicate: {other:?}"),
        }
    }

    #[test]
    fn load_command_profile_from_str_parses_regex_pattern_matcher() {
        let input = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity:
  canonical_name: sgdisk
trust:
  tier: tier_a
  source: built_in
forms:
  - id: inspect
    selector:
      kind: has_positional_at_matching
      index: 0
      matcher:
        kind: regex_pattern
        pattern: '^\\d+:(show|get)(:[[:xdigit:]]+)?$'
modifiers: []
extensions: {}
"#;

        let profile = load_command_profile_from_str(input).expect("expected normalized profile");

        match &profile.forms[0].selector {
            SelectorExpr::Predicate(SelectorPredicate::HasPositionalAtMatching(
                index,
                ValueMatcher::RegexPattern(pattern),
            )) => {
                assert_eq!(*index, 0);
                assert_eq!(pattern, "^\\\\d+:(show|get)(:[[:xdigit:]]+)?$");
            }
            other => panic!("unexpected selector predicate: {other:?}"),
        }
    }

    #[test]
    fn load_command_profile_from_str_surfaces_normalize_errors() {
        let input = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity:
  canonical_name: bash
  aliases:
    - sh-compatible
    - sh-compatible
trust:
  tier: tier_a
  source: built_in
forms: []
modifiers: []
extensions: {}
"#;

        let error = load_command_profile_from_str(input).expect_err("expected normalize error");

        match error {
            LoadProfileError::Normalize(_) => {}
            other => panic!("expected normalize error, got {other:?}"),
        }
    }

    #[test]
    fn load_command_profile_from_path_reads_bash_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("bash.yaml");

        let profile = load_command_profile_from_path(&profile_path)
            .expect("expected bash profile file to load");

        assert_eq!(profile.primary_name(), "bash");
        assert_eq!(profile.identity.aliases.len(), 1);
        assert_eq!(profile.forms.len(), 5);
        assert_eq!(profile.modifiers.len(), 1);

        let form_ids: Vec<&str> = profile.forms.iter().map(|form| form.id.as_str()).collect();
        assert_eq!(
            form_ids,
            vec![
                "command_string",
                "script_file",
                "stdin_script_explicit",
                "stdin_script_implicit",
                "interactive",
            ]
        );

        match &profile.forms[0].selector {
            SelectorExpr::Predicate(SelectorPredicate::HasFlag(flag_name)) => {
                assert_eq!(flag_name.as_str(), "-c")
            }
            other => panic!("unexpected selector predicate: {other:?}"),
        }

        match &profile.forms[1].parameters[0].semantic {
            SemanticType::Path(semantic) => {
                assert_eq!(semantic.role, PathRole::Read);
                assert_eq!(semantic.purpose, Some(PathPurpose::ScriptSource));
            }
            other => panic!("unexpected script_file semantic: {other:?}"),
        }

        assert_eq!(
            profile.forms[0].parameters[0].binding,
            BindingSpec::FollowingFlag {
                flag_name: crate::FlagName::new("-c"),
                operand_mode: crate::FlagOperandMode::NextPositionalAfterDashDash,
            }
        );
        assert_eq!(
            profile.forms[1].parameters[0].binding,
            BindingSpec::NextPositional
        );
        assert_eq!(
            profile.modifiers[0].parameters[0].binding,
            BindingSpec::FollowingMatchedFlag {
                operand_mode: crate::FlagOperandMode::NextArg,
            }
        );

        assert_eq!(profile.modifiers[0].effects[0].kind, EffectKind::LoadConfig);
    }

    #[test]
    fn load_command_profile_from_path_reads_sh_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("sh.yaml");

        let profile = load_command_profile_from_path(&profile_path)
            .expect("expected sh profile file to load");

        assert_eq!(profile.primary_name(), "sh");
        assert_eq!(
            profile
                .identity
                .aliases
                .iter()
                .map(|alias| alias.as_str())
                .collect::<Vec<_>>(),
            vec!["ash", "dash"]
        );
        assert_eq!(profile.forms.len(), 5);
        assert!(profile.modifiers.is_empty());

        let form_ids: Vec<&str> = profile.forms.iter().map(|form| form.id.as_str()).collect();
        assert_eq!(
            form_ids,
            vec![
                "command_string",
                "script_file",
                "stdin_script_explicit",
                "stdin_script_implicit",
                "interactive",
            ]
        );

        match &profile.forms[0].selector {
            SelectorExpr::Predicate(SelectorPredicate::HasFlag(flag_name)) => {
                assert_eq!(flag_name.as_str(), "-c")
            }
            other => panic!("unexpected selector predicate: {other:?}"),
        }

        match &profile.forms[0].parameters[0].semantic {
            SemanticType::Payload(semantic) => {
                assert_eq!(semantic.language, crate::PayloadLanguage::Sh);
                assert_eq!(semantic.source, crate::PayloadSource::InlineString);
                assert!(semantic.recursive);
            }
            other => panic!("unexpected command_string semantic: {other:?}"),
        }

        match &profile.forms[1].parameters[0].semantic {
            SemanticType::Path(semantic) => {
                assert_eq!(semantic.role, PathRole::Read);
                assert_eq!(semantic.purpose, Some(PathPurpose::ScriptSource));
            }
            other => panic!("unexpected script_file semantic: {other:?}"),
        }

        assert_eq!(
            profile.forms[0].parameters[0].binding,
            BindingSpec::FollowingFlag {
                flag_name: crate::FlagName::new("-c"),
                operand_mode: crate::FlagOperandMode::NextPositionalAfterDashDash,
            }
        );
        assert_eq!(
            profile.forms[1].parameters[0].binding,
            BindingSpec::NextPositional
        );
    }

    #[test]
    fn load_command_profile_from_path_reads_cp_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("cp.yaml");

        let profile = load_command_profile_from_path(&profile_path)
            .expect("expected cp profile file to load");

        let form_ids: Vec<&str> = profile.forms.iter().map(|form| form.id.as_str()).collect();

        assert_eq!(profile.primary_name(), "cp");
        assert_eq!(profile.forms.len(), 10);
        assert_eq!(
            form_ids,
            vec![
                "show_help",
                "show_version",
                "target_directory",
                "target_directory_attributes_only",
                "target_directory_hard_link",
                "target_directory_symbolic_link",
                "default_attributes_only",
                "default_hard_link",
                "default_symbolic_link",
                "default_copy"
            ]
        );
        assert!(profile.modifiers.len() > 1);

        let default_copy = profile
            .forms
            .iter()
            .find(|form| form.id.as_str() == "default_copy")
            .expect("expected default_copy form to exist");

        assert_eq!(
            default_copy.parameters[0].binding,
            BindingSpec::RemainingPositionalsBeforeLast
        );
        assert_eq!(
            default_copy.parameters[1].binding,
            BindingSpec::LastPositional
        );
        let preserve_default = profile
            .modifiers
            .iter()
            .find(|modifier| modifier.id.as_str() == "preserve_default")
            .expect("expected preserve_default modifier");
        assert_eq!(
            preserve_default.parameters[0].binding,
            BindingSpec::FollowingMatchedFlag {
                operand_mode: crate::FlagOperandMode::InlineOnly,
            }
        );
    }

    #[test]
    fn load_command_profile_from_str_parses_inline_or_short_attached_operand_mode() {
        let input = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity:
  canonical_name: fdisk
  aliases: []
trust:
  tier: tier_a
  source: built_in
forms:
  - id: interactive
    selector:
      kind: has_positional_at
      index: 0
    parameters:
      - name: target
        semantic:
          kind: path
          role: write
          purpose: generic_operand
        binding:
          kind: next_positional
        cardinality: required_one
    effects:
      - kind: write_path
        target:
          kind: slot
          name: target
modifiers:
  - id: compatibility
    matcher:
      kind: any_flag
      flags:
        - "-c"
        - "--compatibility"
    parameters:
      - name: compatibility_mode
        semantic:
          kind: plain_value
        binding:
          kind: following_matched_flag
          operand_mode: inline_or_short_attached
        cardinality: optional_one
extensions: {}
"#;

        let profile = load_command_profile_from_str(input).expect("expected YAML profile to parse");

        assert_eq!(
            profile.modifiers[0].parameters[0].binding,
            BindingSpec::FollowingMatchedFlag {
                operand_mode: crate::FlagOperandMode::InlineOrShortAttached,
            }
        );
    }

    #[test]
    fn load_command_profile_from_path_reads_install_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("install.yaml");

        let profile = load_command_profile_from_path(&profile_path)
            .expect("expected install profile file to load");

        let form_ids: Vec<&str> = profile.forms.iter().map(|form| form.id.as_str()).collect();

        assert_eq!(profile.primary_name(), "install");
        assert_eq!(
            form_ids,
            vec![
                "show_help",
                "show_version",
                "create_directories",
                "target_directory",
                "default_install"
            ]
        );
        assert!(profile.modifiers.len() > 1);
        assert_eq!(
            profile.forms[4].parameters[0].binding,
            BindingSpec::RemainingPositionalsBeforeLast
        );
        assert_eq!(
            profile.forms[4].parameters[1].binding,
            BindingSpec::LastPositional
        );
    }

    #[test]
    fn load_command_profile_from_path_reads_tee_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("tee.yaml");

        let profile = load_command_profile_from_path(&profile_path)
            .expect("expected tee profile file to load");

        let form_ids: Vec<&str> = profile.forms.iter().map(|form| form.id.as_str()).collect();

        assert_eq!(profile.primary_name(), "tee");
        assert_eq!(profile.forms.len(), 3);
        assert_eq!(
            form_ids,
            vec!["show_help", "show_version", "duplicate_stream"]
        );
        assert!(profile.modifiers.len() > 1);
        assert_eq!(
            profile.forms[2].parameters[0].binding,
            BindingSpec::RemainingPositionals
        );
        assert_eq!(
            profile.forms[2].stream_contract,
            Some(crate::StreamContract {
                stdin_mode: crate::StreamInputMode::DataRequired,
                stdout_mode: crate::StreamOutputMode::Data,
                stderr_mode: crate::StreamOutputMode::Opaque,
            })
        );
    }

    #[test]
    fn load_command_profile_from_path_reads_env_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("env.yaml");

        let profile = load_command_profile_from_path(&profile_path)
            .expect("expected env profile file to load");

        let form_ids: Vec<&str> = profile.forms.iter().map(|form| form.id.as_str()).collect();

        assert_eq!(profile.primary_name(), "env");
        assert_eq!(form_ids, vec!["dispatch_with_env", "print_environment"]);
        assert_eq!(profile.modifiers.len(), 9);
        assert_eq!(
            profile.forms[0].effects[0].kind,
            EffectKind::DispatchCommand
        );
        assert_eq!(
            profile.forms[0].parameters[0].binding,
            BindingSpec::LeadingPositionalsWhile(crate::ValueMatcher::StructuredValueContext(
                crate::StructuredValueContext::EnvAssignment,
            ))
        );
    }

    #[test]
    fn load_command_profile_from_path_reads_grep_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("grep.yaml");

        let profile = load_command_profile_from_path(&profile_path)
            .expect("expected grep profile file to load");

        let form_ids: Vec<&str> = profile.forms.iter().map(|form| form.id.as_str()).collect();
        let modifier_ids: Vec<&str> = profile
            .modifiers
            .iter()
            .map(|modifier| modifier.id.as_str())
            .collect();

        assert_eq!(profile.primary_name(), "grep");
        assert_eq!(profile.identity.aliases.len(), 2);
        assert_eq!(
            form_ids,
            vec!["explicit_pattern_search", "positional_pattern_search"]
        );
        assert!(modifier_ids.contains(&"inline_pattern"));
        assert!(modifier_ids.contains(&"pattern_file"));
        assert!(modifier_ids.contains(&"recursive"));
        assert_eq!(
            profile.forms[1].parameters[0].binding,
            BindingSpec::NextPositional
        );
        assert_eq!(
            profile.forms[1].parameters[1].binding,
            BindingSpec::RemainingPositionals
        );
        assert_eq!(
            profile.forms[0].stream_contract,
            Some(crate::StreamContract {
                stdin_mode: crate::StreamInputMode::DataOptional,
                stdout_mode: crate::StreamOutputMode::Data,
                stderr_mode: crate::StreamOutputMode::Opaque,
            })
        );

        match &profile.modifiers[1].parameters[0].semantic {
            SemanticType::Path(semantic) => {
                assert_eq!(semantic.role, PathRole::Read);
                assert_eq!(semantic.purpose, Some(PathPurpose::GenericOperand));
            }
            other => panic!("unexpected grep pattern_file semantic: {other:?}"),
        }

        assert_eq!(
            profile.forms[0].parameters[0].value_constraints,
            vec![crate::ValueConstraint::ExcludeLiteral("-".to_string())]
        );
    }

    #[test]
    fn load_command_profile_from_path_reads_gzip_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("gzip.yaml");

        let profile =
            load_command_profile_from_path(&profile_path).expect("expected gzip profile to load");

        assert_eq!(profile.primary_name(), "gzip");
        assert_eq!(profile.forms.len(), 1);
        assert_eq!(profile.forms[0].id.as_str(), "default_file_mode");
        assert_eq!(
            profile.forms[0].parameters[0].binding,
            BindingSpec::RemainingPositionals
        );
        assert_eq!(profile.forms[0].effects[0].kind, EffectKind::ReadPath);
        assert_eq!(profile.forms[0].effects[1].kind, EffectKind::WritePath);
        assert!(matches!(
            profile.forms[0].effects[1].target,
            EffectTarget::DerivedPath(_)
        ));
    }

    #[test]
    fn load_command_profile_from_path_reads_gunzip_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("gunzip.yaml");

        let profile =
            load_command_profile_from_path(&profile_path).expect("expected gunzip profile to load");

        assert_eq!(profile.primary_name(), "gunzip");
        assert_eq!(profile.forms.len(), 1);
        assert_eq!(profile.forms[0].id.as_str(), "default_file_mode");
        assert_eq!(
            profile.forms[0].parameters[0].binding,
            BindingSpec::RemainingPositionals
        );
        assert_eq!(profile.forms[0].effects[0].kind, EffectKind::ReadPath);
        assert_eq!(profile.forms[0].effects[1].kind, EffectKind::WritePath);
        assert!(matches!(
            profile.forms[0].effects[1].target,
            EffectTarget::DerivedPath(_)
        ));
    }

    #[test]
    fn load_command_profile_from_path_reads_zcat_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("zcat.yaml");

        let profile =
            load_command_profile_from_path(&profile_path).expect("expected zcat profile to load");

        assert_eq!(profile.primary_name(), "zcat");
        assert!(profile.matches_name("gzcat"));
        assert_eq!(profile.forms.len(), 1);
        assert_eq!(profile.forms[0].id.as_str(), "decompress_stream");
        assert_eq!(
            profile.forms[0].parameters[0].binding,
            BindingSpec::RemainingPositionals
        );
        assert_eq!(profile.forms[0].effects[0].kind, EffectKind::ReadPath);
        assert_eq!(profile.forms[0].effects[1].kind, EffectKind::TransformData);
    }

    #[test]
    fn load_command_profile_from_path_reads_iconv_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("iconv.yaml");

        let profile =
            load_command_profile_from_path(&profile_path).expect("expected iconv profile to load");

        assert_eq!(profile.primary_name(), "iconv");
        assert_eq!(profile.forms.len(), 2);
        assert_eq!(profile.forms[0].id.as_str(), "convert_to_stdout");
        assert_eq!(profile.forms[1].id.as_str(), "convert_to_file");
        assert_eq!(profile.forms[1].effects[1].kind, EffectKind::TransformData);
        assert_eq!(profile.modifiers[2].id.as_str(), "output_path");
    }

    #[test]
    fn load_command_profile_from_path_reads_jq_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("jq.yaml");

        let profile =
            load_command_profile_from_path(&profile_path).expect("expected jq profile to load");

        let modifier_ids: Vec<&str> = profile
            .modifiers
            .iter()
            .map(|modifier| modifier.id.as_str())
            .collect();

        assert_eq!(profile.primary_name(), "jq");
        assert_eq!(profile.forms.len(), 4);
        assert_eq!(profile.forms[0].id.as_str(), "filter_program");
        assert_eq!(profile.forms[1].id.as_str(), "filter_program_file");
        assert!(modifier_ids.contains(&"filter_file"));
        assert!(modifier_ids.contains(&"rawfile"));
        assert!(modifier_ids.contains(&"slurpfile"));
        assert!(modifier_ids.contains(&"argfile"));
        assert!(modifier_ids.contains(&"null_input"));
        assert!(matches!(
            &profile.modifiers[0].effects[0].target,
            EffectTarget::Slot(slot) if slot.as_str() == "filter_files"
        ));
        let rawfile = profile
            .modifiers
            .iter()
            .find(|modifier| modifier.id.as_str() == "rawfile")
            .expect("expected rawfile modifier");
        assert_eq!(
            rawfile.parameters[0].binding,
            BindingSpec::FollowingMatchedFlag {
                operand_mode: crate::FlagOperandMode::SecondArg,
            }
        );
        assert!(matches!(
            &rawfile.effects[0].target,
            EffectTarget::Slot(slot) if slot.as_str() == "rawfile_paths"
        ));
    }

    #[test]
    fn load_command_profile_from_path_reads_head_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("head.yaml");

        let profile = load_command_profile_from_path(&profile_path)
            .expect("expected head profile file to load");

        let modifier_ids: Vec<&str> = profile
            .modifiers
            .iter()
            .map(|modifier| modifier.id.as_str())
            .collect();

        assert_eq!(profile.primary_name(), "head");
        assert_eq!(profile.forms.len(), 1);
        assert_eq!(profile.forms[0].id.as_str(), "read_inputs");
        assert_eq!(
            profile.forms[0].parameters[0].binding,
            BindingSpec::RemainingPositionals
        );
        assert_eq!(
            profile.forms[0].parameters[0].value_constraints,
            vec![crate::ValueConstraint::ExcludeLiteral("-".to_string())]
        );
        assert!(modifier_ids.contains(&"bytes"));
        assert!(modifier_ids.contains(&"lines"));
        assert!(modifier_ids.contains(&"quiet"));
        assert!(modifier_ids.contains(&"verbose"));
        assert!(modifier_ids.contains(&"zero_terminated"));
        assert_eq!(
            profile.forms[0].stream_contract,
            Some(crate::StreamContract {
                stdin_mode: crate::StreamInputMode::DataOptional,
                stdout_mode: crate::StreamOutputMode::Data,
                stderr_mode: crate::StreamOutputMode::Opaque,
            })
        );
    }

    #[test]
    fn load_command_profile_from_path_reads_sudo_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("sudo.yaml");

        let profile = load_command_profile_from_path(&profile_path)
            .expect("expected sudo profile file to load");

        assert_eq!(profile.primary_name(), "sudo");
        assert_eq!(profile.forms.len(), 1);
        assert_eq!(profile.forms[0].id.as_str(), "wrapped_command");
        assert_eq!(profile.modifiers.len(), 18);
        assert_eq!(
            profile.forms[0].effects[0].kind,
            EffectKind::PrivilegeModifier
        );
        assert_eq!(
            profile.forms[0].effects[1].kind,
            EffectKind::DispatchCommand
        );
        assert_eq!(
            profile.forms[0].parameters[0].binding,
            BindingSpec::LeadingPositionalsWhile(crate::ValueMatcher::StructuredValueContext(
                crate::StructuredValueContext::EnvAssignment,
            ))
        );
    }

    #[test]
    fn load_command_profile_from_path_reads_timeout_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("timeout.yaml");

        let profile = load_command_profile_from_path(&profile_path)
            .expect("expected timeout profile file to load");

        let modifier_ids: Vec<&str> = profile
            .modifiers
            .iter()
            .map(|modifier| modifier.id.as_str())
            .collect();

        assert_eq!(profile.primary_name(), "timeout");
        assert_eq!(profile.forms.len(), 1);
        assert_eq!(profile.forms[0].id.as_str(), "wrapped_command");
        assert_eq!(profile.forms[0].parameters.len(), 3);
        assert_eq!(
            profile.forms[0].parameters[0].binding,
            BindingSpec::NextPositional
        );
        assert_eq!(
            profile.forms[0].parameters[1].binding,
            BindingSpec::NextPositional
        );
        assert_eq!(
            profile.forms[0].parameters[2].binding,
            BindingSpec::RemainingArgs
        );
        assert_eq!(
            profile.forms[0].effects[0].kind,
            EffectKind::DispatchCommand
        );
        assert!(modifier_ids.contains(&"signal"));
        assert!(modifier_ids.contains(&"kill_after"));
        assert!(modifier_ids.contains(&"foreground"));
        assert!(modifier_ids.contains(&"preserve_status"));
        assert!(modifier_ids.contains(&"verbose"));
    }

    #[test]
    fn load_command_profile_from_path_reads_stdbuf_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("stdbuf.yaml");

        let profile =
            load_command_profile_from_path(&profile_path).expect("expected stdbuf profile to load");

        let modifier_ids: Vec<&str> = profile
            .modifiers
            .iter()
            .map(|modifier| modifier.id.as_str())
            .collect();

        assert_eq!(profile.primary_name(), "stdbuf");
        assert_eq!(profile.forms.len(), 1);
        assert_eq!(profile.forms[0].id.as_str(), "wrapped_command");
        assert_eq!(profile.forms[0].parameters.len(), 2);
        assert_eq!(
            profile.forms[0].parameters[0].binding,
            BindingSpec::NextPositional
        );
        assert_eq!(
            profile.forms[0].parameters[1].binding,
            BindingSpec::RemainingArgs
        );
        assert_eq!(
            profile.forms[0].effects[0].kind,
            EffectKind::DispatchCommand
        );
        assert!(modifier_ids.contains(&"input"));
        assert!(modifier_ids.contains(&"output"));
        assert!(modifier_ids.contains(&"error"));
    }

    #[test]
    fn load_command_profile_from_path_reads_pip_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("pip.yaml");

        let profile =
            load_command_profile_from_path(&profile_path).expect("expected pip profile to load");

        assert_eq!(profile.primary_name(), "pip");
        assert_eq!(profile.identity.aliases.len(), 1);
        assert_eq!(profile.identity.aliases[0].as_str(), "pip3");

        let subcommands = profile
            .subcommands
            .as_ref()
            .expect("expected pip subcommands to be present");
        assert_eq!(subcommands.roots.len(), 1);
        assert_eq!(subcommands.roots[0].name, "install");
        assert_eq!(subcommands.roots[0].forms.len(), 1);

        let form = &subcommands.roots[0].forms[0];
        assert_eq!(form.id.as_str(), "install_packages");
        assert_eq!(form.parameters.len(), 1);
        assert_eq!(
            form.parameters[0].binding,
            BindingSpec::RemainingPositionals
        );
        assert_eq!(
            form.parameters[0].cardinality,
            crate::Cardinality::OptionalMany
        );

        match &form.parameters[0].semantic {
            SemanticType::PackageLocator(locator) => {
                assert_eq!(locator.manager, crate::PackageManagerKind::Pip);
                assert_eq!(
                    locator.locator_kinds,
                    vec![
                        crate::PackageLocatorKind::RegistryRef,
                        crate::PackageLocatorKind::LocalPath,
                        crate::PackageLocatorKind::DirectUrl,
                        crate::PackageLocatorKind::VcsUrl,
                        crate::PackageLocatorKind::UnknownDynamic,
                    ]
                );
            }
            other => panic!("unexpected pip package semantic: {other:?}"),
        }

        let effect_kinds: Vec<EffectKind> = form.effects.iter().map(|effect| effect.kind).collect();
        assert_eq!(
            effect_kinds,
            vec![
                EffectKind::ImportPackage,
                EffectKind::ExecuteImportedPackageLogic,
            ]
        );
        assert_eq!(
            form.effects[0].target,
            EffectTarget::Slot(crate::SlotName::new("package_specs"))
        );
        assert_eq!(
            form.effects[1].target,
            EffectTarget::Slot(crate::SlotName::new("package_specs"))
        );

        assert_eq!(subcommands.roots[0].modifiers.len(), 3);
        let requirement_modifier = &subcommands.roots[0].modifiers[0];
        assert_eq!(requirement_modifier.id.as_str(), "requirement_file");
        assert_eq!(requirement_modifier.parameters.len(), 1);
        assert_eq!(
            requirement_modifier.parameters[0].binding,
            BindingSpec::FollowingMatchedFlag {
                operand_mode: crate::FlagOperandMode::NextArg,
            }
        );

        match &requirement_modifier.parameters[0].semantic {
            SemanticType::PackageLocator(locator) => {
                assert_eq!(locator.manager, crate::PackageManagerKind::Pip);
                assert_eq!(
                    locator.locator_kinds,
                    vec![
                        crate::PackageLocatorKind::RequirementFile,
                        crate::PackageLocatorKind::LocalPath,
                        crate::PackageLocatorKind::UnknownDynamic,
                    ]
                );
            }
            other => panic!("unexpected pip requirement semantic: {other:?}"),
        }

        let editable_modifier = &subcommands.roots[0].modifiers[1];
        assert_eq!(editable_modifier.id.as_str(), "editable_package");
        assert_eq!(editable_modifier.parameters.len(), 1);
        match &editable_modifier.parameters[0].semantic {
            SemanticType::PackageLocator(locator) => {
                assert_eq!(locator.manager, crate::PackageManagerKind::Pip);
                assert_eq!(
                    locator.locator_kinds,
                    vec![
                        crate::PackageLocatorKind::LocalPath,
                        crate::PackageLocatorKind::VcsUrl,
                        crate::PackageLocatorKind::DirectUrl,
                        crate::PackageLocatorKind::UnknownDynamic,
                    ]
                );
            }
            other => panic!("unexpected pip editable semantic: {other:?}"),
        }

        let target_modifier = &subcommands.roots[0].modifiers[2];
        assert_eq!(target_modifier.id.as_str(), "target_directory");
        assert_eq!(target_modifier.parameters.len(), 1);
        assert_eq!(
            target_modifier.parameters[0].binding,
            BindingSpec::FollowingMatchedFlag {
                operand_mode: crate::FlagOperandMode::NextArg,
            }
        );
        assert!(matches!(
            target_modifier.parameters[0].semantic,
            SemanticType::Path(_)
        ));
    }

    #[test]
    fn load_command_profile_from_path_reads_apt_get_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("apt-get.yaml");

        let profile = load_command_profile_from_path(&profile_path)
            .expect("expected apt-get profile to load");

        assert_eq!(profile.primary_name(), "apt-get");

        let subcommands = profile
            .subcommands
            .as_ref()
            .expect("expected apt-get subcommands to be present");
        assert_eq!(subcommands.roots.len(), 2);
        assert_eq!(subcommands.roots[0].name, "install");
        assert_eq!(subcommands.roots[1].name, "source");

        let install_form = &subcommands.roots[0].forms[0];
        assert_eq!(install_form.id.as_str(), "install_packages");
        match &install_form.parameters[0].semantic {
            SemanticType::PackageLocator(locator) => {
                assert_eq!(locator.manager, crate::PackageManagerKind::Apt);
                assert_eq!(
                    locator.locator_kinds,
                    vec![
                        crate::PackageLocatorKind::RegistryRef,
                        crate::PackageLocatorKind::UnknownDynamic,
                    ]
                );
            }
            other => panic!("unexpected apt-get install semantic: {other:?}"),
        }

        let source_form = &subcommands.roots[1].forms[0];
        assert_eq!(source_form.id.as_str(), "source_packages");
        match &source_form.parameters[0].semantic {
            SemanticType::PackageLocator(locator) => {
                assert_eq!(locator.manager, crate::PackageManagerKind::Apt);
                assert_eq!(
                    locator.locator_kinds,
                    vec![crate::PackageLocatorKind::RegistryRef,]
                );
            }
            other => panic!("unexpected apt-get source semantic: {other:?}"),
        }
    }

    #[test]
    fn load_command_profile_from_path_reads_conan_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("conan.yaml");

        let profile =
            load_command_profile_from_path(&profile_path).expect("expected conan profile to load");

        assert_eq!(profile.primary_name(), "conan");

        let subcommands = profile
            .subcommands
            .as_ref()
            .expect("expected conan subcommands to be present");
        assert_eq!(subcommands.roots.len(), 1);
        assert_eq!(subcommands.roots[0].name, "install");
        assert_eq!(subcommands.roots[0].forms.len(), 2);

        let form_ids: Vec<&str> = subcommands.roots[0]
            .forms
            .iter()
            .map(|form| form.id.as_str())
            .collect();
        assert!(form_ids.contains(&"install_requirements"));
        assert!(form_ids.contains(&"install_requirement_reference"));
        let modifier_ids: Vec<&str> = subcommands.roots[0]
            .modifiers
            .iter()
            .map(|modifier| modifier.id.as_str())
            .collect();
        assert!(modifier_ids.contains(&"requires"));
        assert!(modifier_ids.contains(&"tool_requires"));
    }

    #[test]
    fn load_command_profile_from_path_reads_less_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("less.yaml");

        let profile =
            load_command_profile_from_path(&profile_path).expect("expected less profile to load");

        assert_eq!(profile.primary_name(), "less");
        assert_eq!(profile.forms.len(), 1);
        assert_eq!(profile.forms[0].id.as_str(), "interactive_read");

        let effects = &profile.forms[0].effects;
        assert_eq!(effects.len(), 2);
        assert_eq!(effects[0].kind, EffectKind::ReadPath);
        assert_eq!(effects[1].kind, EffectKind::OpenInteractiveEscapeSurface);

        let surface = effects[1]
            .interactive_escape_surface
            .as_ref()
            .expect("expected interactive escape surface");
        assert_eq!(
            surface.kind,
            caushell_types::InteractiveEscapeSurfaceKind::Pager
        );
        assert!(surface.requires_tty);
        assert_eq!(
            surface.capabilities,
            vec![
                caushell_types::InteractiveEscapeCapability::SpawnShell,
                caushell_types::InteractiveEscapeCapability::LaunchExternalEditor,
            ]
        );
    }

    #[test]
    fn load_command_profile_from_path_reads_vim_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("vim.yaml");

        let profile =
            load_command_profile_from_path(&profile_path).expect("expected vim profile to load");

        assert_eq!(profile.primary_name(), "vim");
        assert_eq!(profile.identity.aliases.len(), 1);
        assert_eq!(profile.forms.len(), 2);
        assert_eq!(profile.forms[0].id.as_str(), "script_mode");
        assert_eq!(profile.forms[1].id.as_str(), "interactive_editor");

        let surface = profile.forms[1].effects[1]
            .interactive_escape_surface
            .as_ref()
            .expect("expected vim interactive escape surface");
        assert_eq!(
            surface.kind,
            caushell_types::InteractiveEscapeSurfaceKind::Editor
        );
        assert!(surface.requires_tty);
        assert_eq!(
            surface.capabilities,
            vec![
                caushell_types::InteractiveEscapeCapability::SpawnShell,
                caushell_types::InteractiveEscapeCapability::RunCommand,
                caushell_types::InteractiveEscapeCapability::WriteBufferToPath,
            ]
        );
    }

    #[test]
    fn load_command_profile_from_path_reads_ed_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("ed.yaml");

        let profile =
            load_command_profile_from_path(&profile_path).expect("expected ed profile to load");

        assert_eq!(profile.primary_name(), "ed");
        assert_eq!(profile.forms.len(), 2);
        assert_eq!(profile.forms[0].id.as_str(), "stdin_script_mode");
        assert_eq!(profile.forms[1].id.as_str(), "interactive_editor");
        assert_eq!(profile.forms[0].implicit_inputs.len(), 1);
        assert_eq!(
            profile.forms[0].implicit_inputs[0].source,
            crate::ImplicitInputSource::StdinData
        );
        assert_eq!(profile.forms[0].effects[1].kind, EffectKind::ConsumeStdin);

        let surface = profile.forms[1].effects[1]
            .interactive_escape_surface
            .as_ref()
            .expect("expected ed interactive escape surface");
        assert_eq!(
            surface.kind,
            caushell_types::InteractiveEscapeSurfaceKind::LineEditor
        );
        assert!(surface.requires_tty);
        assert_eq!(
            surface.capabilities,
            vec![
                caushell_types::InteractiveEscapeCapability::SpawnShell,
                caushell_types::InteractiveEscapeCapability::WriteBufferToPath,
            ]
        );
    }

    #[test]
    fn load_command_profile_from_path_reads_dd_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("dd.yaml");

        let profile =
            load_command_profile_from_path(&profile_path).expect("expected dd profile to load");

        let form_ids: Vec<&str> = profile.forms.iter().map(|form| form.id.as_str()).collect();

        assert_eq!(profile.primary_name(), "dd");
        assert_eq!(profile.forms.len(), 3);
        assert_eq!(form_ids, vec!["show_help", "show_version", "raw_copy"]);
        assert_eq!(
            profile.forms[2].parameters[0].binding,
            BindingSpec::ArgsWithPrefix("if=".to_string())
        );
        assert_eq!(
            profile.forms[2].parameters[1].binding,
            BindingSpec::ArgsWithPrefix("of=".to_string())
        );
        let effect_kinds: Vec<EffectKind> = profile.forms[2]
            .effects
            .iter()
            .map(|effect| effect.kind)
            .collect();
        assert_eq!(
            effect_kinds,
            vec![EffectKind::ReadPath, EffectKind::WritePath]
        );
    }

    #[test]
    fn load_command_profile_from_path_reads_mkfs_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("mkfs.yaml");

        let profile =
            load_command_profile_from_path(&profile_path).expect("expected mkfs profile to load");

        assert_eq!(profile.primary_name(), "mkfs");
        assert_eq!(profile.forms.len(), 6);
        let form_ids: Vec<&str> = profile.forms.iter().map(|form| form.id.as_str()).collect();
        assert_eq!(
            form_ids,
            vec![
                "show_help",
                "show_version",
                "dry_run_filesystem_target",
                "dry_run_filesystem_target_with_trailing_size",
                "filesystem_target",
                "filesystem_target_with_trailing_size"
            ]
        );
        assert_eq!(
            profile.forms[2].parameters[0].binding,
            BindingSpec::LastPositional
        );
        assert_eq!(
            profile.forms[3].parameters[0].binding,
            BindingSpec::LastPositionalBeforeLast
        );
        assert_eq!(
            profile.forms[3].parameters[1].binding,
            BindingSpec::LastPositional
        );
        assert_eq!(
            profile.forms[4].parameters[0].binding,
            BindingSpec::LastPositional
        );
        assert_eq!(
            profile.forms[5].parameters[0].binding,
            BindingSpec::LastPositionalBeforeLast
        );
        assert_eq!(
            profile.forms[5].parameters[1].binding,
            BindingSpec::LastPositional
        );
        assert_eq!(profile.forms[4].effects.len(), 1);
        assert_eq!(profile.forms[4].effects[0].kind, EffectKind::WritePath);
    }

    #[test]
    fn load_command_profile_from_path_reads_wipefs_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("wipefs.yaml");

        let profile =
            load_command_profile_from_path(&profile_path).expect("expected wipefs profile to load");

        let form_ids: Vec<&str> = profile.forms.iter().map(|form| form.id.as_str()).collect();
        assert_eq!(profile.primary_name(), "wipefs");
        assert_eq!(profile.forms.len(), 5);
        assert_eq!(
            form_ids,
            vec![
                "show_help",
                "show_version",
                "inspect_device",
                "preview_wipe_device_signatures",
                "wipe_device_signatures"
            ]
        );
        assert_eq!(
            profile.forms[2].parameters[0].binding,
            BindingSpec::RemainingPositionals
        );
        let modifier_ids: Vec<&str> = profile
            .modifiers
            .iter()
            .map(|modifier| modifier.id.as_str())
            .collect();
        assert!(modifier_ids.contains(&"destructive_all"));
        assert!(modifier_ids.contains(&"no_act"));
        assert!(modifier_ids.contains(&"offset"));
    }

    #[test]
    fn load_command_profile_from_path_reads_sgdisk_profile_file() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join("sgdisk.yaml");

        let profile =
            load_command_profile_from_path(&profile_path).expect("expected sgdisk profile to load");

        let form_ids: Vec<&str> = profile.forms.iter().map(|form| form.id.as_str()).collect();
        assert_eq!(profile.primary_name(), "sgdisk");
        assert_eq!(profile.forms.len(), 12);
        assert_eq!(
            form_ids,
            vec![
                "show_help",
                "show_usage",
                "show_version",
                "list_partition_types",
                "inspect_device",
                "inspect_partition_info",
                "backup_partition_table",
                "simulate_partition_table_mutation",
                "mutate_partition_table_state",
                "mutate_partition_layout",
                "mutate_partition_table",
                "inspect_partition_attributes"
            ]
        );
        assert_eq!(
            profile.forms[8].parameters[0].binding,
            BindingSpec::LastPositional
        );
        let modifier_ids: Vec<&str> = profile
            .modifiers
            .iter()
            .map(|modifier| modifier.id.as_str())
            .collect();
        assert!(modifier_ids.contains(&"pretend"));
        assert!(modifier_ids.contains(&"delete_partition"));
        assert!(modifier_ids.contains(&"destructive_partition_table"));
    }
}
