//! Namespace contracts describe every possible configured-target branch.
use caushell_profile::{
    LoadProfileError, NormalizeError, load_command_profile_from_str,
    load_raw_command_profile_from_str,
};
use serde_json::{Value, json};

fn profile(target: Value, contract: Option<&str>) -> Value {
    let mut effect = json!({"kind": "write_path", "target": target});
    if let Some(contract) = contract {
        effect["namespace_effect"] = json!(contract);
    }
    json!({
        "dsl_version": "caushell.profile/v1alpha1", "kind": "command_profile",
        "identity": {"canonical_name": "arbitrary-producer"},
        "forms": [{"id": "run", "parameters": [
            {"name": "inputs", "semantic": {"kind": "path", "role": "read"},
             "binding": {"kind": "remaining_positionals"}, "cardinality": "required_many"},
            {"name": "destination", "semantic": {"kind": "path", "role": "write"},
             "binding": {"kind": "following_flag", "flag": "-o", "operand_mode": "next_arg"},
             "cardinality": "optional_one"}
        ], "effects": [effect]}]
    })
}

fn providers() -> Vec<Value> {
    vec![
        json!({}),
        json!({"sources": [{"slot": "destination", "projection": {"kind": "identity"}}]}),
        json!({"environment": {"name": "OUTPUT_ROOT", "empty_is_unset": true}}),
        json!({"shell_variable": {"name": "output_root", "empty_is_unset": true}}),
        json!({"default_value": "/output", "missing": "skip"}),
    ]
}

fn target(provider: Value) -> Value {
    let mut value = json!({"kind": "configured_path", "sources": [], "missing": "unknown"});
    value
        .as_object_mut()
        .unwrap()
        .extend(provider.as_object().unwrap().clone());
    value
}

fn accepted(profile: &Value) {
    load_command_profile_from_str(&profile.to_string())
        .unwrap_or_else(|e| panic!("{e}: {profile}"));
}

fn rejected_namespace_shape(profile: &Value) {
    let source = profile.to_string();
    // Distinguish semantic validation from malformed YAML or an unrelated slot error.
    load_raw_command_profile_from_str(&source).unwrap();
    assert!(
        matches!(
            load_command_profile_from_str(&source),
            Err(LoadProfileError::Normalize(
                NormalizeError::InvalidPathAccess(_)
            ))
        ),
        "expected namespace-shape rejection: {source}"
    );
}

#[test]
fn scalar_configured_targets_keep_the_regular_file_contract() {
    for provider in providers() {
        for empty_family in [false, true] {
            let mut target = target(provider.clone());
            if empty_family {
                target["fallback_parent_slots"] = json!([]);
            }
            accepted(&profile(target, Some("regular_file_write")));
        }
    }
}

#[test]
fn an_input_parent_family_is_not_a_regular_file_even_with_a_scalar_primary_source() {
    for name in ["arbitrary-producer", "renamed-output-tool"] {
        for suffix in [None, Some("objects"), Some("artifacts/bytecode")] {
            for provider in providers() {
                let mut target = target(provider);
                target["fallback_parent_slots"] = json!(["inputs"]);
                if let Some(suffix) = suffix {
                    target["fallback_parent_suffix"] = json!(suffix);
                }
                let mut source = profile(target, Some("directory_tree_write"));
                source["identity"]["canonical_name"] = json!(name);
                accepted(&source);
                source["forms"][0]["effects"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("namespace_effect");
                accepted(&source);
                source["forms"][0]["effects"][0]["namespace_effect"] = json!("regular_file_write");
                rejected_namespace_shape(&source);
            }
        }
    }
}

#[test]
fn nested_forms_modifiers_and_dispatch_overrides_validate_the_same_target_shape() {
    let mut family = target(json!({}));
    family["fallback_parent_slots"] = json!(["inputs"]);
    let original = profile(family, Some("directory_tree_write"));
    for location in [
        "form",
        "modifier",
        "subcommand_form",
        "subcommand_modifier",
        "dispatch_override",
    ] {
        let mut source = original.clone();
        let form = source["forms"][0].clone();
        let effect = form["effects"][0].clone();
        let mut no_effect = form.clone();
        no_effect["effects"] = json!([]);
        let modifier = json!({"id": "emit", "matcher": {"kind": "any_flag", "flags": ["--emit"]}, "effects": [effect]});
        match location {
            "form" => {}
            "modifier" => {
                source["forms"] = json!([no_effect]);
                source["modifiers"] = json!([modifier]);
            }
            "subcommand_form" => {
                source["forms"] = json!([]);
                source["subcommands"] = json!({"roots": [{"name": "emit", "forms": [form]}]});
            }
            "subcommand_modifier" => {
                source["forms"] = json!([]);
                source["subcommands"] = json!({"roots": [{"name": "emit", "forms": [no_effect], "modifiers": [modifier]}]});
            }
            "dispatch_override" => {
                source["forms"] = json!([]);
                source["option_scope"] = json!("leading_options");
                source["subcommands"] = json!({"roots": [{"name": "emit", "forms": [no_effect]}]});
                source["dispatch_overrides"] = json!([{"subcommand_depth": 0, "first_arguments": ["--emit"], "forms": [form]}]);
            }
            _ => unreachable!(),
        }
        accepted(&source);
        let invalid: Value = serde_json::from_str(
            &source
                .to_string()
                .replace("directory_tree_write", "regular_file_write"),
        )
        .unwrap();
        rejected_namespace_shape(&invalid);
    }
}
