//! Manifest task dialects. File observations and recursive shell analysis stay
//! in the existing resolution pipeline.
use caushell_profile::{BoundInvocation, EffectKind, EffectTarget};
use serde_json::Value;
pub(crate) fn decoded_task_arguments(
    bound: &caushell_profile::BoundInvocation,
    slot: &str,
) -> Option<Vec<String>> {
    let mut args = Vec::new();
    for parameter in bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
    {
        for value in parameter.semantic_values() {
            match value {
                caushell_profile::SemanticValueRef::Projected { value, .. } => {
                    match &value.resolution {
                        caushell_profile::SemanticValueResolution::Known(text) => {
                            args.push(text.clone())
                        }
                        _ => return None,
                    }
                }
                caushell_profile::SemanticValueRef::Original(
                    caushell_profile::BoundValue::Argument {
                        text,
                        quoted,
                        node_kind,
                        span,
                        materialization,
                        ..
                    },
                ) => {
                    let argument = caushell_profile::ProjectedArg {
                        word_context: Default::default(),
                        text: text.clone(),
                        quoted: *quoted,
                        node_kind: node_kind.clone(),
                        span: span.clone(),
                        implicit_input_source: None,
                        runtime_argument_domain: None,
                        runtime_data: *materialization
                            != caushell_profile::BoundArgumentMaterialization::Literal,
                        substitution_shape: None,
                        lexical_field_prefix: None,
                        kind: caushell_profile::ProjectedArgKind::Positional,
                    };
                    args.push(
                        caushell_profile::argument_structure(&argument)
                            .exact_value()?
                            .to_owned(),
                    );
                }
                _ => return None,
            }
        }
    }
    Some(args)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManifestTaskDialect {
    Npm,
    Yarn,
    Composer,
}

impl ManifestTaskDialect {
    pub(crate) fn for_invocation(bound: &BoundInvocation) -> Option<(Self, &str)> {
        if !bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ExecuteConfigDefinedTask)
        {
            return None;
        }
        bound.effects.iter().find_map(|effect| {
            let EffectTarget::ToolConventionPath(target) = &effect.target else {
                return None;
            };
            let dialect = match target.convention.as_str() {
                "npm.package_json"
                    if matches!(bound.form_id.as_str(), "run_script" | "test_script") =>
                {
                    Self::Npm
                }
                "node.package_manifest"
                    if bound.form_id.as_str() == "package_script_or_install" =>
                {
                    Self::Yarn
                }
                "composer.script_definition" if bound.form_id.as_str() == "run_script" => {
                    Self::Composer
                }
                _ => return None,
            };
            Some((dialect, target.path.as_str()))
        })
    }
}

pub(crate) struct ManifestTaskBody {
    pub name: String,
    pub body: Option<String>,
}

fn task(name: &str, body: Option<String>) -> ManifestTaskBody {
    ManifestTaskBody {
        name: name.to_owned(),
        body,
    }
}

pub(crate) fn quote_task_argument(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn append_arguments(body: &str, args: &[String]) -> String {
    let mut body = body.to_owned();
    for arg in args {
        body.push(' ');
        body.push_str(&quote_task_argument(arg));
    }
    body
}

pub(crate) fn yarn_task_name(args: &[String]) -> Option<&str> {
    match args.first().map(String::as_str) {
        None | Some("install") => Some("install"),
        Some("run") => args.get(1).map(String::as_str),
        Some(name) => Some(name),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskSelection {
    Selected,
    NoTask,
    Unresolved,
}

pub(crate) fn yarn_task_selection(args: &[String], ignore_install_scripts: bool) -> TaskSelection {
    if args.is_empty() || args.first().is_some_and(|s| s == "install") {
        let install_args = args.get(1..).unwrap_or_default();
        if install_args.iter().any(|s| {
            !matches!(
                s.as_str(),
                "--ignore-scripts"
                    | "--frozen-lockfile"
                    | "--immutable"
                    | "--non-interactive"
                    | "--offline"
                    | "--ignore-engines"
                    | "--ignore-optional"
                    | "--production"
            )
        }) {
            return TaskSelection::Unresolved;
        }
        if ignore_install_scripts || install_args.iter().any(|s| s == "--ignore-scripts") {
            TaskSelection::NoTask
        } else {
            TaskSelection::Selected
        }
    } else {
        let Some(name) = yarn_task_name(args) else {
            return TaskSelection::Unresolved;
        };
        if name.is_empty() || name.starts_with('-') {
            TaskSelection::Unresolved
        } else if args.first().is_some_and(|s| s != "run") && yarn_builtin(name) {
            TaskSelection::NoTask
        } else {
            TaskSelection::Selected
        }
    }
}

pub(crate) fn yarn_tasks(
    value: &Value,
    args: &[String],
    ignore_install_scripts: bool,
) -> Vec<ManifestTaskBody> {
    match yarn_task_selection(args, ignore_install_scripts) {
        TaskSelection::NoTask => return Vec::new(),
        TaskSelection::Unresolved => {
            return vec![task(
                yarn_task_name(args)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("<unresolved-task>"),
                None,
            )];
        }
        TaskSelection::Selected => {}
    }
    let Some(scripts) = value.get("scripts").and_then(Value::as_object) else {
        return Vec::new();
    };
    let major = value
        .get("packageManager")
        .and_then(Value::as_str)
        .and_then(|s| s.strip_prefix("yarn@"))
        .and_then(|s| s.split('.').next())
        .and_then(|s| s.parse::<u32>().ok());
    let install = args.is_empty() || args.first().is_some_and(|s| s == "install");
    if install {
        let mut tasks = Vec::new();
        for name in [
            "preinstall",
            "install",
            "postinstall",
            "prepublish",
            "prepare",
        ] {
            if let Some(body) = scripts.get(name) {
                let conditional = matches!(name, "prepublish" | "prepare");
                if conditional && major.is_some_and(|v| v >= 2) {
                    continue;
                }
                // Classic's final two hooks depend on the production/install
                // configuration, unlike the three common install events.
                tasks.push(task(
                    name,
                    if conditional {
                        None
                    } else {
                        body.as_str().map(str::to_owned)
                    },
                ));
            }
        }
        return tasks;
    }
    let explicit_run = args.first().is_some_and(|s| s == "run");
    let Some(name) = yarn_task_name(args) else {
        return Vec::new();
    };
    let Some(body) = scripts.get(name) else {
        return Vec::new();
    };
    let forwarded = &args[if explicit_run { 2 } else { 1 }..];
    let forwarded = forwarded
        .strip_prefix(&["--".to_owned()])
        .unwrap_or(forwarded);
    let mut tasks = Vec::new();
    for event in [format!("pre{name}"), name.to_owned(), format!("post{name}")] {
        if event == name {
            // Modern Yarn's portable shell consumes positional parameters
            // rather than appending argv when they are referenced explicitly.
            let body = body.as_str().and_then(|s| {
                if !forwarded.is_empty() && s.contains('$') && major != Some(1) {
                    None
                } else {
                    Some(append_arguments(s, forwarded))
                }
            });
            tasks.push(task(&event, body));
        } else if major.is_none_or(|v| v < 2) {
            if let Some(body) = scripts.get(&event) {
                tasks.push(task(
                    &event,
                    if major == Some(1) {
                        body.as_str().map(str::to_owned)
                    } else {
                        None
                    },
                ));
            }
        }
    }
    tasks
}

fn yarn_builtin(name: &str) -> bool {
    matches!(
        name,
        "access"
            | "add"
            | "audit"
            | "autoclean"
            | "bin"
            | "cache"
            | "check"
            | "config"
            | "constraints"
            | "create"
            | "dedupe"
            | "dlx"
            | "exec"
            | "explain"
            | "generate-lock-entry"
            | "global"
            | "help"
            | "import"
            | "info"
            | "init"
            | "install"
            | "licenses"
            | "link"
            | "list"
            | "lockfile"
            | "login"
            | "logout"
            | "node"
            | "npm"
            | "outdated"
            | "owner"
            | "pack"
            | "patch"
            | "patch-commit"
            | "plugin"
            | "policies"
            | "prune"
            | "publish"
            | "rebuild"
            | "remove"
            | "run"
            | "set"
            | "stage"
            | "tag"
            | "team"
            | "unlink"
            | "unplug"
            | "up"
            | "upgrade"
            | "upgrade-interactive"
            | "version"
            | "versions"
            | "why"
            | "workspace"
            | "workspaces"
    )
}

pub(crate) fn composer_tasks(value: &Value, name: &str, args: &[String]) -> Vec<ManifestTaskBody> {
    let Some(scripts) = value.get("scripts").and_then(Value::as_object) else {
        return Vec::new();
    };
    let Some(body) = scripts.get(name) else {
        return Vec::new();
    };
    let bodies: Vec<&Value> = match body {
        Value::Array(items) => items.iter().collect(),
        _ => vec![body],
    };
    bodies
        .into_iter()
        .map(|body| {
            task(
                name,
                body.as_str().and_then(|body| composer_body(body, args)),
            )
        })
        .collect()
}

fn composer_body(body: &str, args: &[String]) -> Option<String> {
    let no_args = body.contains("@no_additional_args");
    let body = body
        .replace(" @no_additional_args", "")
        .replace("@no_additional_args", "");
    let args = if no_args { &[][..] } else { args };
    if body.starts_with('@') && !body.starts_with("@php ") && !body.starts_with("@putenv ") {
        // Composer references split on literal spaces, not shell syntax.
        let mut fields = body[1..].split(' ');
        let name = fields.next()?;
        if name == "composer" {
            return None;
        }
        let mut forwarded = Vec::new();
        let mut inserted = false;
        for field in fields {
            if field == "@additional_args" {
                forwarded.extend_from_slice(args);
                inserted = true;
            } else {
                forwarded.push(field.to_owned());
            }
        }
        if !inserted {
            forwarded.extend_from_slice(args);
        }
        // References re-enter the existing recursive frontier, including its
        // depth limit, instead of expanding an unbounded JSON call tree here.
        let command = format!("composer run-script {} --", quote_task_argument(name));
        return Some(append_arguments(&command, &forwarded));
    }
    if body.starts_with("@putenv ")
        || (!body.contains(' ')
            && (body.contains("::") || (body.contains('\\') && body.ends_with("Command"))))
    {
        return None;
    }
    // PHP sources retain their executable-language boundary, not an unknown
    // executable name beginning with '@'.
    let body = if let Some(tail) = body.strip_prefix("@php ") {
        format!("php {tail}")
    } else {
        body
    };
    let escaped = args
        .iter()
        .map(|s| quote_task_argument(s))
        .collect::<Vec<_>>()
        .join(" ");
    Some(if body.contains("@additional_args") {
        body.replace("@additional_args", &escaped)
    } else {
        append_arguments(&body, args)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn composer_arrays_references_and_arguments_are_not_shell_fragments() {
        let value = json!({"scripts":{"x":["printf %s", "@other 'quoted'", "Handler::run"]}});
        let tasks = composer_tasks(&value, "x", &["x; rm -rf /".into()]);
        assert_eq!(tasks[0].body.as_deref(), Some("printf %s 'x; rm -rf /'"));
        assert_eq!(
            tasks[1].body.as_deref(),
            Some("composer run-script 'other' -- ''\\''quoted'\\''' 'x; rm -rf /'")
        );
        assert!(tasks[2].body.is_none());
        assert_eq!(
            composer_body("rm -rf @no_additional_args", &["/".into()]).as_deref(),
            Some("rm -rf")
        );
        assert_eq!(
            composer_body("rm @additional_args -rf", &["/".into()]).as_deref(),
            Some("rm '/' -rf")
        );
    }

    #[test]
    fn yarn_dialect_does_not_confuse_install_and_run_hooks() {
        let mut value = json!({"packageManager":"yarn@1.22.22", "scripts":{"prex":"printf PRE","x":"printf %s","postx":"printf POST","preinstall":"rm -rf /", "install":"printf INSTALL"}});
        let tasks = yarn_tasks(&value, &["run".into(), "x".into(), "/".into()], false);
        assert_eq!(
            tasks.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
            ["prex", "x", "postx"]
        );
        assert_eq!(tasks[1].body.as_deref(), Some("printf %s '/'"));
        assert_eq!(
            yarn_tasks(&value, &[], false)[0].body.as_deref(),
            Some("rm -rf /")
        );
        assert!(yarn_tasks(&value, &[], true).is_empty());
        value["packageManager"] = json!("yarn@4.0.0");
        assert_eq!(yarn_tasks(&value, &["x".into()], false).len(), 1);
        value.as_object_mut().unwrap().remove("packageManager");
        assert!(yarn_tasks(&value, &["x".into()], false)[0].body.is_none());
    }
}
