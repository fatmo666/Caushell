use caushell_profile::*;
use caushell_types::{
    ShellKind, ShellReferenceTarget as T, ShellScalarValue as S, StructuredShellValue as V,
};

fn array(bindings: &mut SessionBindings, values: &[(u64, &str)], complete: bool) {
    bindings.insert_structured(
        "items",
        V::IndexedArray {
            elements: values.iter().map(|(k, v)| (*k, S::exact(*v))).collect(),
            complete,
        },
    );
}

fn args(command: &str, bindings: &SessionBindings) -> MaterializedProjectedInvocation {
    let parsed = caushell_parse::parse_command(command, ShellKind::Bash).unwrap();
    materialize_projected_invocation(
        &project_invocation(
            &parsed.commands[0],
            InvocationRuntimeContext::new().with_shell_kind(ShellKind::Bash),
        ),
        bindings,
    )
}

fn exact(result: &MaterializedProjectedInvocation) -> Vec<&str> {
    assert!(
        result.arg_resolutions.iter().all(|r| matches!(
            r,
            ValueMaterialization::Static
                | ValueMaterialization::ResolvedExactScalar { .. }
                | ValueMaterialization::ResolvedRuntimeProduced { .. }
                | ValueMaterialization::ResolvedShellWord { .. }
        )),
        "{result:#?}"
    );
    result
        .invocation
        .args
        .iter()
        .map(|a| a.text.as_str())
        .collect()
}

#[test]
fn quoted_lists_keep_sparse_order_empty_fields_and_native_data() {
    let mut bindings = SessionBindings::new();
    array(
        &mut bindings,
        &[(9, "a b"), (2, ""), (15, "'$(not-executed)' *")],
        true,
    );
    let result = args("printf '%s' \"${items[@]}\" tail", &bindings);
    assert_eq!(
        exact(&result),
        ["%s", "", "a b", "'$(not-executed)' *", "tail"]
    );
    assert!(
        result
            .invocation
            .args
            .iter()
            .skip(1)
            .take(3)
            .all(|a| a.runtime_data)
    );
    array(&mut bindings, &[], true);
    assert_eq!(
        exact(&args("printf '%s' \"${items[@]}\" tail", &bindings)),
        ["%s", "tail"]
    );
    array(&mut bindings, &[(0, "")], true);
    assert_eq!(
        exact(&args("printf '%s' \"${items[@]}\"", &bindings)),
        ["%s", ""]
    );
}

#[test]
fn selections_indirection_and_references_share_scalar_resolution() {
    let mut bindings = SessionBindings::new();
    array(&mut bindings, &[(2, "dir with spaces/file")], true);
    bindings.insert_structured(
        "map",
        V::AssociativeArray {
            elements: [("selected key".into(), S::exact("--no-insecure"))].into(),
            complete: true,
        },
    );
    bindings.insert_exact_scalar("selector", "items[2]");
    bindings.insert_structured(
        "ref",
        V::NameReference {
            target: T::Variable {
                name: "selector".into(),
            },
        },
    );
    assert_eq!(
        exact(&args(
            "printf '%s' \"${items[2]}\" \"${map['selected key']}\" \"${!selector}\" \"$ref\"",
            &bindings
        )),
        [
            "%s",
            "dir with spaces/file",
            "--no-insecure",
            "dir with spaces/file",
            "items[2]"
        ]
    );
    bindings.insert_structured(
        "ref",
        V::NameReference {
            target: T::IndexedElement {
                name: "items".into(),
                index: 2,
            },
        },
    );
    assert_eq!(
        exact(&args(
            "printf '%s' \"$ref\" \"prefix/${items[2]}\"",
            &bindings
        )),
        ["%s", "dir with spaces/file", "prefix/dir with spaces/file"]
    );
    array(&mut bindings, &[(2, "changed")], true);
    assert_eq!(
        exact(&args("printf '%s' \"$ref\"", &bindings)),
        ["%s", "changed"]
    );
}

#[test]
fn partial_unknown_cyclic_and_side_effecting_references_do_not_materialize() {
    let mut bindings = SessionBindings::new();
    assert_eq!(
        shell_array_index("9223372036854775807", &bindings),
        Some(i64::MAX as u64)
    );
    for index in ["9223372036854775808", "18446744073709551615"] {
        assert_eq!(shell_array_index(index, &bindings), None);
    }
    array(&mut bindings, &[(2, "known")], false);
    assert_eq!(
        exact(&args("printf '%s' \"${items[2]}\"", &bindings)),
        ["%s", "known"]
    );
    for word in [
        "\"${items[@]}\"",
        "\"${items[3]}\"",
        "\"${items[i++]}\"",
        "\"${items[$(touch /outside)]}\"",
        "${items[@]}",
    ] {
        let result = args(&format!("printf '%s' {word}"), &bindings);
        assert!(
            result.arg_resolutions.iter().any(|r| !matches!(
                r,
                ValueMaterialization::Static
                    | ValueMaterialization::ResolvedExactScalar { .. }
                    | ValueMaterialization::ResolvedShellWord { .. }
            )),
            "{word}: {result:#?}"
        );
    }
    bindings.insert_structured(
        "a",
        V::NameReference {
            target: T::Variable { name: "b".into() },
        },
    );
    bindings.insert_structured(
        "b",
        V::NameReference {
            target: T::Variable { name: "a".into() },
        },
    );
    assert!(resolve_shell_reference(&bindings, T::Variable { name: "a".into() }).is_err());
    for index in 0..20 {
        bindings.insert_structured(
            &format!("ref{index}"),
            V::NameReference {
                target: T::Variable {
                    name: format!("ref{}", index + 1),
                },
            },
        );
    }
    assert!(
        resolve_shell_reference(
            &bindings,
            T::Variable {
                name: "ref0".into()
            }
        )
        .is_err()
    );
    array(&mut bindings, &[(0, "zero")], true);
    assert!(
        resolve_shell_reference(
            &bindings,
            T::IndexedElement {
                name: "items".into(),
                index: 0
            }
        )
        .is_ok()
    );
    bindings.insert_structured(
        "items",
        V::IndexedArray {
            elements: (0..257).map(|index| (index, S::exact("x"))).collect(),
            complete: true,
        },
    );
    assert!(
        materialize_exact_shell_parameter_reference_fields("${items[@]}", true, &bindings)
            .is_none()
    );
}

#[test]
fn selected_runtime_input_keeps_capture_and_source_type() {
    let mut bindings = SessionBindings::new();
    bindings.insert_structured(
        "items",
        V::IndexedArray {
            elements: [(
                0,
                S::RuntimeInput {
                    source: caushell_types::RuntimeInputSource::StdinData,
                    capture: caushell_types::RuntimeInputCapture::Descriptor {
                        descriptor: "fd:3".into(),
                    },
                },
            )]
            .into(),
            complete: true,
        },
    );
    let value = resolve_shell_reference(
        &bindings,
        T::IndexedElement {
            name: "items".into(),
            index: 0,
        },
    )
    .unwrap();
    assert!(matches!(value.value, SessionValue::RuntimeInput { .. }));
    let result = args("printf '%s' \"${items[0]}\"", &bindings);
    assert!(
        matches!(&result.arg_resolutions[1], ValueMaterialization::RequiresRuntimeInput { capture: Some(caushell_types::RuntimeInputCapture::Descriptor { descriptor }), .. } if descriptor == "fd:3")
    );
}

#[test]
fn structured_values_do_not_borrow_bash_indexing_in_other_shells() {
    let mut bindings = SessionBindings::new();
    array(&mut bindings, &[(0, "known")], true);
    bindings.set_shell_kind(ShellKind::Zsh);
    assert!(
        resolve_shell_reference(
            &bindings,
            T::IndexedElement {
                name: "items".into(),
                index: 0
            }
        )
        .is_err()
    );
    assert!(shell_reference_target("items[0]", &bindings).is_none());
    bindings.insert_exact_scalar("plain", "known");
    assert!(
        resolve_shell_reference(
            &bindings,
            T::Variable {
                name: "plain".into()
            }
        )
        .is_ok()
    );
}
