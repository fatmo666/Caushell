//! Declarative configured-path resolution. Only argv and supplied cwd/home are
//! inspected; no filesystem/configuration discovery or process probing occurs.
use caushell_profile::{
    BoundInvocation, ConfiguredPathMissing, ConfiguredPathTarget, SemanticValueResolution,
    ValueProjection, project_value,
};
use caushell_types::PathResolution;

use super::normalize::{join_shell_path, normalize_shell_path};

pub(super) struct ConfiguredPathResolution {
    pub resolution: PathResolution,
    pub cwd_dependent: bool,
    pub implicit_incidental_cache: bool,
}

fn last_value(
    invocation: &BoundInvocation,
    slot: &str,
    projection: &ValueProjection,
) -> Option<SemanticValueResolution> {
    invocation
        .bound_parameters
        .iter()
        .find(|parameter| parameter.name.as_str() == slot)?
        .values
        .iter()
        .filter_map(|value| project_value(projection, value))
        .last()
}

fn unknown(text: impl Into<String>) -> PathResolution {
    PathResolution::UnsupportedDynamicText { text: text.into() }
}

/// Python-style expandvars may expand even shell-quoted literal data. This does
/// not evaluate command substitution or shell syntax. Without a tool environment
/// fact, preserve uncertainty instead of reading the guard's own environment.
fn contains_environment_reference(text: &str) -> bool {
    let mut chars = text.chars();
    while let Some(character) = chars.next() {
        if character == '$'
            && chars
                .clone()
                .next()
                .is_some_and(|next| next == '{' || next == '_' || next.is_alphanumeric())
        {
            return true;
        }
    }
    false
}

fn expand_path_text(
    text: &str,
    expand_environment: bool,
    expand_user: bool,
    home: Option<&str>,
) -> Result<String, PathResolution> {
    if expand_environment && contains_environment_reference(text) {
        return Err(unknown(format!(
            "tool environment expansion is unresolved: {text}"
        )));
    }
    if expand_user && text.starts_with('~') {
        if text == "~" || text.starts_with("~/") {
            let Some(home) = home.filter(|home| home.starts_with('/')) else {
                return Err(PathResolution::HomeUnavailable { text: text.into() });
            };
            return Ok(format!("{home}{}", &text[1..]));
        }
        return Err(unknown(format!(
            "named-user home expansion is unresolved: {text}"
        )));
    }
    Ok(text.into())
}

fn concrete(text: &str, cwd: &str) -> (PathResolution, bool) {
    let relative = !text.starts_with('/');
    let path = if relative {
        join_shell_path(cwd, text)
    } else {
        normalize_shell_path(text)
    };
    (PathResolution::Concrete { path }, relative)
}

pub(super) fn resolve_configured_path(
    invocation: &BoundInvocation,
    target: &ConfiguredPathTarget,
    cwd: &str,
    home: Option<&str>,
    record: Option<crate::support::ExecutionResolveRecordRef<'_>>,
) -> Option<ConfiguredPathResolution> {
    let selected = target
        .sources
        .iter()
        .find_map(|source| last_value(invocation, source.slot.as_str(), &source.projection))
        .or_else(|| {
            target
                .environment
                .as_ref()
                .and_then(|env| crate::support::environment_default(env, record))
        })
        .or_else(|| {
            target
                .default_value
                .as_ref()
                .map(|value| SemanticValueResolution::Known(value.clone()))
        });
    let Some(selected) = selected else {
        return match target.missing {
            ConfiguredPathMissing::Skip => None,
            missing => Some(ConfiguredPathResolution {
                resolution: unknown(
                    "configured path depends on undiscovered configuration/defaults",
                ),
                cwd_dependent: false,
                implicit_incidental_cache: missing == ConfiguredPathMissing::IncidentalCache,
            }),
        };
    };
    let SemanticValueResolution::Known(text) = selected else {
        return Some(ConfiguredPathResolution {
            resolution: unknown(format!(
                "explicit configured path is unresolved: {selected:?}"
            )),
            cwd_dependent: true,
            implicit_incidental_cache: false,
        });
    };
    let result = expand_path_text(&text, target.expand_environment, target.expand_user, home)
        .and_then(|text| {
            // An absolute destination is independent of rootdir and cwd.
            if text.starts_with('/') || target.relative_to.is_none() {
                return Ok(concrete(&text, cwd));
            }
            let anchor = target.relative_to.as_ref().unwrap();
            let (root, parent) =
                match last_value(invocation, anchor.slot.as_str(), &ValueProjection::Identity) {
                    Some(value) => (value, false),
                    None => match anchor.fallback_parent_slot.as_ref().and_then(|slot| {
                        last_value(invocation, slot.as_str(), &ValueProjection::Identity)
                    }) {
                        Some(value) => (value, true),
                        None => {
                            return Err(unknown(
                                "relative configured path has no statically known anchor",
                            ));
                        }
                    },
                };
            let SemanticValueResolution::Known(root) = root else {
                return Err(unknown(format!(
                    "configured path anchor is unresolved: {root:?}"
                )));
            };
            let root = expand_path_text(&root, !parent && anchor.expand_environment, false, home)?;
            let (root_resolution, cwd_dependent) = concrete(&root, cwd);
            let root = root_resolution.concrete_path().unwrap();
            let root = if parent {
                root.rsplit_once('/')
                    .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
                    .unwrap_or("/")
            } else {
                root
            };
            Ok((
                PathResolution::Concrete {
                    path: join_shell_path(root, &text),
                },
                cwd_dependent,
            ))
        });
    let (resolution, cwd_dependent) = result.unwrap_or_else(|unknown| (unknown, true));
    Some(ConfiguredPathResolution {
        resolution,
        cwd_dependent,
        implicit_incidental_cache: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use caushell_parse::parse_command;
    use caushell_profile::{
        BoundValue, EffectTarget, ImplicitInputSource, InvocationRuntimeContext, ProfileRegistry,
        ResolveInvocationResult, load_command_profile_from_str, resolve_invocation,
    };
    use caushell_types::{RuntimeArgumentDomain, ShellKind};

    const PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: configured-tool}
forms:
  - id: run
    effects:
      - kind: write_path
        target:
          kind: configured_path
          sources:
            - {slot: output, projection: {kind: identity}}
            - {slot: overrides, projection: {kind: key_value, key: path, separator: '='}}
modifiers:
  - id: output
    matcher: {kind: any_flag, flags: ['--output']}
    parameters:
      - {name: output, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: optional_many}
  - id: overrides
    matcher: {kind: any_flag, flags: ['--ini']}
    parameters:
      - {name: overrides, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: optional_many}
"#;

    fn bound(command: &str) -> (BoundInvocation, ConfiguredPathTarget) {
        let registry =
            ProfileRegistry::from_profiles(vec![load_command_profile_from_str(PROFILE).unwrap()])
                .unwrap();
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationResult::Resolved(resolved) = resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
        ) else {
            panic!("{command}")
        };
        let EffectTarget::ConfiguredPath(target) = &resolved.bound.effects[0].target else {
            panic!()
        };
        (resolved.bound.clone(), target.clone())
    }

    #[test]
    fn missing_unknown_and_inapplicable_are_distinct() {
        let (bound, mut target) = bound("configured-tool --ini unrelated=anything");
        assert!(resolve_configured_path(&bound, &target, "/work", None, None).is_none());
        target.purpose = Some(caushell_profile::PathPurpose::IncidentalCache);
        target.missing = ConfiguredPathMissing::Unknown;
        let path = resolve_configured_path(&bound, &target, "/work", None, None).unwrap();
        assert!(path.resolution.concrete_path().is_none());
        assert!(!path.implicit_incidental_cache); // Purpose alone is not a bypass.
        target.missing = ConfiguredPathMissing::IncidentalCache;
        assert!(
            resolve_configured_path(&bound, &target, "/work", None, None)
                .unwrap()
                .implicit_incidental_cache
        );
    }

    #[test]
    fn explicit_unknown_does_not_fall_back_to_a_lower_source_or_default() {
        let (bound, mut target) =
            bound("configured-tool --output \"$UNKNOWN\" --ini path=/work/safe");
        target.missing = ConfiguredPathMissing::IncidentalCache;
        target.purpose = Some(caushell_profile::PathPurpose::IncidentalCache);
        let path = resolve_configured_path(&bound, &target, "/work", None, None).unwrap();
        assert!(path.resolution.concrete_path().is_none());
        assert!(!path.implicit_incidental_cache);
        target.missing = ConfiguredPathMissing::Skip;
        target.default_value = Some("safe-default".into());
        assert!(
            resolve_configured_path(&bound, &target, "/work", None, None)
                .unwrap()
                .resolution
                .concrete_path()
                .is_none()
        );
    }

    #[test]
    fn last_applicable_value_wins_without_mutating_source_arguments() {
        let (bound, target) = bound(
            "configured-tool --ini path=/outside --ini path=/work/cache --ini unrelated=value",
        );
        let original = bound.clone();
        let path = resolve_configured_path(&bound, &target, "/work", None, None).unwrap();
        assert_eq!(path.resolution.concrete_path(), Some("/work/cache"));
        assert_eq!(bound, original);
    }

    #[test]
    fn tool_expansion_is_opt_in_and_literal_argv_is_not_shell_source() {
        let (bound, mut target) = bound("configured-tool --output '/work/$TOKEN*'");
        assert_eq!(
            resolve_configured_path(&bound, &target, "/work", None, None)
                .unwrap()
                .resolution
                .concrete_path(),
            Some("/work/$TOKEN*")
        );
        target.expand_environment = true;
        assert!(
            resolve_configured_path(&bound, &target, "/work", None, None)
                .unwrap()
                .resolution
                .concrete_path()
                .is_none()
        );
    }

    #[test]
    fn runtime_operand_bounds_do_not_become_substring_bounds_or_cache_defaults() {
        let (mut bound, mut target) = bound("configured-tool --ini path=/work/cache");
        bound.bound_parameters[0].values = vec![BoundValue::ImplicitInput {
            source: ImplicitInputSource::StdinData,
            domain: Some(RuntimeArgumentDomain::PathSet {
                roots: vec!["/work".into()],
                may_escape: false,
            }),
        }];
        target.missing = ConfiguredPathMissing::IncidentalCache;
        target.purpose = Some(caushell_profile::PathPurpose::IncidentalCache);
        let path = resolve_configured_path(&bound, &target, "/work", None, None).unwrap();
        assert!(matches!(
            path.resolution,
            PathResolution::UnsupportedDynamicText { .. }
        ));
        assert!(!path.implicit_incidental_cache);
    }
}
