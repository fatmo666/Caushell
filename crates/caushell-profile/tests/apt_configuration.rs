use caushell_profile::{AptConfiguration, parse_apt_configuration};

fn merge(text: &str) -> AptConfiguration {
    let parsed = parse_apt_configuration(text.as_bytes());
    assert!(parsed.errors.is_empty(), "{parsed:?}");
    let mut config = AptConfiguration::default();
    for item in parsed.options {
        config.apply(item.argument.as_ref().unwrap())
    }
    config
}

#[test]
fn native_scopes_order_case_and_paths_are_data() {
    let mut config = merge(
        r#"
        # Ordinary hash comments do not set configuration.
        // Keys are case-insensitive, values are exact bytes.
        Dir "/work/stage";
        Dir::Cache { Archives "packages"; };
        APT { Get { Download-Only "true"; }; };
        /* A later scalar wins. */ Dir::Cache::Archives "/cache/archives";
    "#,
    );
    assert!(config.errors.is_empty(), "{config:?}");
    assert_eq!(
        config.path("dir::state", "/work").as_deref(),
        Some("/work/stage/var/lib/apt")
    );
    assert_eq!(
        config.path("dir::cache::archives", "/work").as_deref(),
        Some("/cache/archives")
    );
    assert_eq!(config.download_only(), Some(true));
    config.apply("APT::Get::Download-Only=false");
    assert_eq!(config.download_only(), Some(false));
    assert!(
        config.package_outputs("install", "/work").is_none(),
        "real installs are not bounded to manager cache paths"
    );
    assert_eq!(
        config.package_outputs("download", "/work"),
        Some(vec!["/work".into()])
    );
    config.apply("Dir::Cache=../shared");
    assert_eq!(
        config.path("dir::cache", "/work"),
        Some("/work/stage/../shared".into()),
        "do not lexical-normalize away namespace traversal"
    );
}

#[test]
fn hooks_security_controls_and_unknown_semantics_are_never_erased() {
    for option in [
        "APT::Update::Pre-Invoke::=id",
        "dpkg::Pre-Install-Pkgs::=id",
        "Acquire::https::Verify-Peer=false",
        "APT::Get::AllowUnauthenticated=true",
        "Dir::Bin::dpkg=/work/another-program",
        "RootDir=/work/root",
        "Binary::apt-get::APT::Get::Download-Only=true",
        "unknown-control=true",
    ] {
        let mut config = AptConfiguration::default();
        config.apply(option);
        config.apply("Acquire::Retries=3");
        config.apply("APT::Get::Download-Only=true");
        assert!(!config.errors.is_empty(), "{option}");
    }
    let config = merge(r#"DPkg::Pre-Invoke { "first"; "second"; }; Acquire::Retries "3";"#);
    assert_eq!(config.errors.len(), 2);
}

#[test]
fn incomplete_grammar_and_budgets_fail_closed() {
    for text in [
        "#include \"other\";",
        "#clear DPkg::Pre-Invoke;",
        "Dir::Cache /tmp;",
        "Dir::Cache \"x\"",
        "APT { Get \"x\";",
        "Dir \"a\\b\";",
        "Dir \"a\nb\";",
        "};",
        "Dir \"x\";\0",
    ] {
        assert!(
            !parse_apt_configuration(text.as_bytes()).errors.is_empty(),
            "{text:?}"
        );
    }
    assert!(!parse_apt_configuration(&[0xff]).errors.is_empty());
    assert!(
        !parse_apt_configuration(&vec![b' '; 65537])
            .errors
            .is_empty()
    );
    let many = format!("DPkg::Pre-Invoke {{ {} }};", "\"x\";".repeat(2049));
    assert!(!parse_apt_configuration(many.as_bytes()).errors.is_empty());
    assert!(
        !parse_apt_configuration(
            format!("{}\"x\";{}", "a { ".repeat(10), "};".repeat(10)).as_bytes()
        )
        .errors
        .is_empty()
    );
}

#[test]
fn native_data_lists_and_disabled_leaf_caches_do_not_disable_safety_effects() {
    let config = merge(
        r#"
        APT::NeverAutoRemove { "^linux-image"; "^firmware"; };
        APT::VersionedKernelPackages { "linux-.*"; };
        APT::Never-MarkAuto-Sections { "metapackages"; };
        APT::Move-Autobit-Sections { "oldlibs"; };
        APT::AutoRemove::SuggestsImportant "false";
        Acquire::Changelogs::AlwaysOnline "true";
        Acquire::GzipIndexes "true";
        Acquire::CompressionTypes::Order { "xz"; "gz"; };
        Acquire::Languages { "none"; };
        APT::Periodic::Enable "0";
        Dir::Cache::pkgcache "";
        Dir::Cache::srcpkgcache "";
    "#,
    );
    assert!(config.errors.is_empty(), "{config:?}");
    assert!(config.package_outputs("install", "/workspace").is_none());
    assert_eq!(
        config.path("dir::cache::pkgcache", "/workspace"),
        Some(String::new())
    );
    assert!(
        config
            .package_outputs("update", "/workspace")
            .unwrap()
            .iter()
            .all(|p| !p.is_empty())
    );
    for bad in [
        "Dir::Cache=",
        "Dir::State=",
        "Dir::Cache::Archives=",
        "Acquire::CompressionTypes::Order::=custom-helper",
        "APT::Update::Post-Invoke::=id",
        "Acquire::http::User-Agent=secret",
    ] {
        let mut invalid = config.clone();
        invalid.apply(bad);
        assert!(!invalid.errors.is_empty(), "{bad}");
    }
}

#[test]
fn native_configuration_contract_rejects_incompatible_option_grammars() {
    let native = include_str!("../profiles/apt-get.yaml");
    assert!(caushell_profile::load_command_profile_from_str(native).is_ok());
    for incompatible in [
        native.replace(
            "option_scope: leading_options",
            "option_scope: permuted_options",
        ),
        native.replace("['-c', '--config-file']", "['--another-config']"),
    ] {
        assert!(caushell_profile::load_command_profile_from_str(&incompatible).is_err());
    }
}
