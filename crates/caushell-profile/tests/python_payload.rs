use caushell_profile::{PythonEffect as E, PythonInput as I, PythonInputs, analyze_python};
use std::collections::BTreeMap;

#[derive(Default)]
struct Inputs {
    env: BTreeMap<String, Option<String>>,
    files: BTreeMap<String, Vec<u8>>,
}
impl PythonInputs for Inputs {
    fn environment(&mut self, name: &str) -> Result<Option<String>, String> {
        self.env
            .get(name)
            .cloned()
            .ok_or_else(|| format!("unobserved environment {name}"))
    }
    fn file(&mut self, path: &str) -> Result<Vec<u8>, String> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| format!("unobserved file {path}"))
    }
}
#[test]
fn python_argv_is_native_data_and_aliases_are_values() {
    let p = analyze_python(
        "import subprocess as process; launch=process.run; items=['touch','--','$(not-code)']; launch(items,check=True)",
        &[],
        &mut Inputs::default(),
    );
    assert_eq!(p.gap, None, "{p:?}");
    assert_eq!(
        p.effects,
        [E::NativeCommand(vec![
            "touch".into(),
            "--".into(),
            "$(not-code)".into()
        ])]
    );
}
#[test]
fn python_file_decoding_nul_split_and_list_unpack_preserve_bytes_and_fields() {
    let mut input = Inputs::default();
    input
        .files
        .insert("opts".into(), b"--first\0white space\0new\nline\0".to_vec());
    let p = analyze_python(
        "import pathlib,subprocess\nflags=pathlib.Path('opts').read_bytes().decode().split('\\0')[:-1]\nsubprocess.run(['tool',*flags]+['--last'],shell=False)",
        &[],
        &mut input,
    );
    assert_eq!(p.gap, None, "{p:?}");
    assert_eq!(
        p.effects,
        [
            E::ReadFile("opts".into()),
            E::NativeCommand(
                ["tool", "--first", "white space", "new\nline", "--last"]
                    .map(str::to_owned)
                    .to_vec()
            )
        ]
    );
    assert!(matches!(&p.inputs[0], I::File{path,bytes} if path=="opts" && bytes.ends_with(&[0])));
}
#[test]
fn python_environment_uses_presence_not_empty_string_fallback() {
    let mut input = Inputs::default();
    input.env.insert("ACTION".into(), Some("".into()));
    let source = "import os,subprocess; subprocess.run(['tool',os.environ['ACTION']])";
    let p = analyze_python(source, &[], &mut input);
    assert_eq!(p.gap, None, "{p:?}");
    assert_eq!(
        p.effects,
        [E::NativeCommand(vec!["tool".into(), "".into()])]
    );
    input.env.insert("ACTION".into(), None);
    let absent = analyze_python(source, &[], &mut input);
    assert!(absent.gap.unwrap().contains("absent"));
    assert!(absent.effects.is_empty());
    input.env.clear();
    assert!(
        analyze_python(source, &[], &mut input)
            .gap
            .unwrap()
            .contains("unobserved")
    );
}
#[test]
fn python_uri_encoder_is_byte_exact_and_keeps_file_dependency() {
    let mut input = Inputs::default();
    input
        .files
        .insert("data".into(), vec![0, b'/', b' ', b'~', 255, b'\n']);
    let p = analyze_python(
        "from pathlib import Path as P; from urllib.parse import quote_from_bytes as quote; import sys; print(quote(P(sys.argv[1]).read_bytes(),safe=''))",
        &["-c".into(), "data".into()],
        &mut input,
    );
    assert_eq!(p.gap, None, "{p:?}");
    assert_eq!(p.stdout, b"%00%2F%20~%FF%0A\n");
    assert_eq!(p.effects, [E::ReadFile("data".into())]);
}
#[test]
fn python_shell_true_is_not_an_argv_list() {
    let p = analyze_python(
        "import subprocess; subprocess.run('echo ok; touch x',shell=True)",
        &[],
        &mut Inputs::default(),
    );
    assert_eq!(p.gap, None, "{p:?}");
    assert_eq!(p.effects, [E::ShellCommand("echo ok; touch x".into())]);
    for source in [
        "import subprocess; subprocess.run(['echo','x'],shell=True)",
        "import subprocess; subprocess.run('echo x',shell=False)",
    ] {
        assert!(
            analyze_python(source, &[], &mut Inputs::default())
                .gap
                .is_some()
        );
    }
}
#[test]
fn python_partial_program_never_returns_complete_effects_or_stdout() {
    for tail in [
        "unknown()",
        "exec('touch x')",
        "import local_module",
        "if True:\n  print('x')",
        "class H: pass",
        "raise Exception()",
        "while True: pass",
        "subprocess.run=lambda x: x",
        "from pathlib import *",
        "del subprocess.run",
        "x=[v for v in []]",
    ] {
        let source =
            format!("import subprocess\nsubprocess.run(['touch','safe'])\nprint('prefix')\n{tail}");
        let p = analyze_python(&source, &[], &mut Inputs::default());
        assert!(p.gap.is_some(), "{source}: {p:?}");
        assert!(p.effects.is_empty());
        assert!(p.stdout.is_empty());
    }
}
#[test]
fn python_runtime_results_and_custom_process_options_are_not_pure() {
    for source in [
        "import subprocess; print(subprocess.run(['true']))",
        "import subprocess; result=subprocess.run(['true']); subprocess.run([str(result)])",
        "import subprocess; subprocess.run(['true'],executable='other')",
        "import subprocess; subprocess.run(['true'],cwd='elsewhere')",
        "import subprocess; subprocess.run(['true'],env={})",
        "import subprocess; subprocess.run(['true'],preexec_fn=callback)",
        "import subprocess; subprocess.run(['true'],capture_output=True)",
        "import subprocess; subprocess.run(['true'],check=1)",
    ] {
        assert!(
            analyze_python(source, &[], &mut Inputs::default())
                .gap
                .is_some(),
            "{source}"
        );
    }
}
#[test]
fn python_name_rebinding_cannot_reuse_an_old_module_contract() {
    for source in [
        "import subprocess; subprocess=2; subprocess.run(['true'])",
        "print=2; print('x')",
        "from pathlib import Path; Path='x'; Path('p').read_bytes()",
    ] {
        assert!(
            analyze_python(source, &[], &mut Inputs::default())
                .gap
                .is_some(),
            "{source}"
        );
    }
}
#[test]
fn python_strings_slices_and_stdout_match_the_supported_subset() {
    let p = analyze_python(
        "import sys; sys.argv=['new','a','b','c']; print(sys.argv[-1],sys.argv[1:3][0],len('中文'),r'raw\\n',b'\\xff'.decode('utf8','strict'))",
        &[],
        &mut Inputs::default(),
    );
    assert!(p.gap.unwrap().contains("decode failed"));
    let p = analyze_python(
        "import sys; sys.argv=['new','a','b','c']; print(sys.argv[-1],sys.argv[1:3][0],len('中文'),r'raw\\n',end='!')",
        &[],
        &mut Inputs::default(),
    );
    assert_eq!(p.gap, None, "{p:?}");
    assert_eq!(p.stdout, b"c a 2 raw\\n!");
}
#[test]
fn python_budget_and_invalid_syntax_are_explicit_gaps() {
    assert!(
        analyze_python("print('''a\r\nb''')", &[], &mut Inputs::default())
            .gap
            .unwrap()
            .contains("newline")
    );
    assert!(
        analyze_python(
            "import subprocess; subprocess.run('x\\0',shell=True)",
            &[],
            &mut Inputs::default()
        )
        .gap
        .unwrap()
        .contains("invalid")
    );
    assert!(
        analyze_python("print('oops'", &[], &mut Inputs::default())
            .gap
            .unwrap()
            .contains("syntax")
    );
    let source = format!("x='x'\n{}", "x=x+x\n".repeat(20));
    assert!(
        analyze_python(&source, &[], &mut Inputs::default())
            .gap
            .unwrap()
            .contains("budget")
    );
    assert!(
        analyze_python(&"#".repeat(65_537), &[], &mut Inputs::default())
            .gap
            .unwrap()
            .contains("budget")
    );
}

#[test]
fn python_tuple_and_list_types_do_not_collapse() {
    let p = analyze_python(
        "import subprocess; subprocess.run(('tool',)+('x',))",
        &[],
        &mut Inputs::default(),
    );
    assert_eq!(p.gap, None, "{p:?}");
    assert_eq!(
        p.effects,
        [E::NativeCommand(vec!["tool".into(), "x".into()])]
    );
    for source in [
        "x=('a',)+['b']; print(len(x))",
        "x=['a']+('b',); print(len(x))",
    ] {
        assert!(
            analyze_python(source, &[], &mut Inputs::default())
                .gap
                .is_some()
        );
    }
}

#[test]
fn python_mutating_child_invalidates_later_file_reads_and_stdout() {
    let mut inputs = Inputs::default();
    inputs.files.insert("data".into(), b"old".to_vec());
    let p = analyze_python(
        "import subprocess; from pathlib import Path; subprocess.run(['tool']); Path('data').read_bytes()",
        &[],
        &mut inputs,
    );
    assert!(p.gap.unwrap().contains("mutating child"));
    assert!(p.effects.is_empty());
    let p = analyze_python(
        "import subprocess; print('before'); subprocess.run(['tool']); print('after')",
        &[],
        &mut inputs,
    );
    assert_eq!(p.gap, None);
    assert!(!p.stdout_complete);
    assert!(p.stdout.is_empty());
    let p = analyze_python(
        "import subprocess; subprocess.run(['tool']); import pathlib",
        &[],
        &mut inputs,
    );
    assert!(p.gap.unwrap().contains("module load follows"));
}

#[test]
fn python_supported_values_match_cpython() {
    for source in [
        "print('a'+'b',len('中文'),True,None,end='!')",
        "print(r'raw\\n',b'caf\\xc3\\xa9'.decode(),sep='|')",
        "import sys; sys.argv=['new','a','b','c']; print(sys.argv[-1],sys.argv[1:3][0])",
        "print(('a','b')[0],('a',)+('b',))", // unsupported conversion stays a gap
        "from urllib.parse import quote_from_bytes; print(quote_from_bytes(b'\\x00/ ~\\xff\\n',safe=''))",
        "import urllib.parse; encode=urllib.parse.quote_from_bytes; print(encode(b'/ a',safe=''))",
        "print('a\\0b\\0'.split('\\0')[:-1][1])",
    ] {
        let output = std::process::Command::new("/usr/bin/python3")
            .args(["-I", "-S", "-c", source])
            .output()
            .expect("CPython oracle");
        assert!(output.status.success(), "{source}: {:?}", output.stderr);
        let p = analyze_python(source, &[], &mut Inputs::default());
        if source.contains("('a',)+") {
            assert!(p.gap.is_some());
            continue;
        }
        assert_eq!(p.gap, None, "{source}: {p:?}");
        assert!(p.stdout_complete);
        assert_eq!(p.stdout, output.stdout, "{source}");
    }
}

#[test]
fn python_value_depth_and_attribute_depth_are_bounded_across_assignments() {
    let source = format!("x=1\n{}", "x=[x]\n".repeat(2000));
    assert!(
        analyze_python(&source, &[], &mut Inputs::default())
            .gap
            .unwrap()
            .contains("budget")
    );
    let source = format!("import os; os.{}environ", "attr.".repeat(2000));
    assert!(
        analyze_python(&source, &[], &mut Inputs::default())
            .gap
            .unwrap()
            .contains("depth")
    );
    let build = format!("x='{}'\n{}", "a".repeat(1000), "x=x+x\n".repeat(7));
    for use_value in [
        format!("print({})", vec!["x"; 128].join(",")),
        format!("y=[{}]", vec!["x"; 128].join(",")),
        "print('a','b','c','d',sep=x)".into(),
    ] {
        assert!(
            analyze_python(&(build.clone() + &use_value), &[], &mut Inputs::default())
                .gap
                .unwrap()
                .contains("budget")
        );
    }
}

#[test]
fn python_native_argv_matches_cpython_without_interpreting_data_as_shell() {
    let source = "import subprocess; subprocess.run(['/usr/bin/python3','-I','-S','-c','import sys; print(repr(sys.argv[1:]))','white space','new\\nline','','$(not-code)'],check=True)";
    let original = std::process::Command::new("/usr/bin/python3")
        .args(["-I", "-S", "-c", source])
        .output()
        .unwrap();
    assert!(original.status.success());
    let p = analyze_python(source, &[], &mut Inputs::default());
    assert_eq!(p.gap, None);
    let E::NativeCommand(argv) = &p.effects[0] else {
        panic!("native command")
    };
    assert_eq!(argv[0], "/usr/bin/python3");
    let modeled = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .unwrap();
    assert!(modeled.status.success());
    assert_eq!(original.stdout, modeled.stdout);
}

#[test]
fn python_method_receiver_precedes_argument_observations() {
    let mut inputs = Inputs::default();
    inputs.files.insert("body".into(), b"data".to_vec());
    inputs.files.insert("encoding".into(), b"utf8".to_vec());
    let p = analyze_python(
        "from pathlib import Path; print(Path('body').read_bytes().decode(Path('encoding').read_bytes().decode()))",
        &[],
        &mut inputs,
    );
    assert_eq!(p.gap, None, "{p:?}");
    assert_eq!(p.stdout, b"data\n");
    assert_eq!(
        p.effects,
        [E::ReadFile("body".into()), E::ReadFile("encoding".into())]
    );
}
