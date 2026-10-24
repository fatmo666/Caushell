use caushell_profile::{PythonEffect as E, PythonInputs, analyze_python};

struct Inputs;
impl PythonInputs for Inputs {
    fn environment(&mut self, _: &str) -> Result<Option<String>, String> {
        Err("unknown environment".into())
    }
    fn file(&mut self, path: &str) -> Result<Vec<u8>, String> {
        if path == "body" {
            Ok(b"response".to_vec())
        } else {
            Err("unknown file".into())
        }
    }
}
fn check(source: &str) -> caushell_profile::PythonAnalysis {
    analyze_python(source, &["-c".into(), "127.0.0.1".into()], &mut Inputs)
}
const LISTENER: &str = "import socket,sys,json,os\ns=socket.socket()\ns.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\ns.bind((sys.argv[1],19317))\ns.listen(4)\ns.settimeout(4)\n";

#[test]
fn bounded_socket_connections_retain_the_listener_route_and_unknown_input() {
    let source = format!(
        "{LISTENER}print(json.dumps({{'pid':os.getpid(),'bound':s.getsockname()}}),flush=True)\nfor n in range(2):\n    c,addr=s.accept()\n    c.settimeout(2)\n    assert c.recv(64)==b'ping'\n    c.sendall(b'pong')\n    c.close()\ns.close()"
    );
    let p = check(&source);
    assert_eq!(p.gap, None, "{p:?}");
    assert_eq!(
        p.effects,
        [
            E::ListenNetwork {
                host: "127.0.0.1".into(),
                port: 19317
            },
            E::RespondNetwork {
                host: "127.0.0.1".into(),
                port: 19317
            },
            E::RespondNetwork {
                host: "127.0.0.1".into(),
                port: 19317
            },
        ]
    );
    assert!(!p.stdout_complete);
    assert!(p.stdout.is_empty());
}

#[test]
fn received_data_and_assertions_do_not_become_known_control_or_argv() {
    for tail in [
        "c,_=s.accept(); data=c.recv(64); assert data==b'known'; print(data.decode())",
        "c,_=s.accept(); data=c.recv(64)\nif data==b'known':\n    unknown_call()",
        "c,_=s.accept(); assert c.recv(64)==b'ping', unknown_call()",
        "c,_=s.accept(); import subprocess; subprocess.run([c.recv(64)])",
    ] {
        let p = check(&format!("{LISTENER}{tail}"));
        assert!(p.gap.is_some(), "{tail}: {p:?}");
        assert!(p.effects.is_empty());
        assert!(p.stdout.is_empty());
    }
}

#[test]
fn socket_handles_share_state_and_reject_unmodeled_operations() {
    let bound = check("import socket; s=socket.socket(); s.bind(('0.0.0.0',1234)); s.close()");
    assert_eq!(bound.gap, None);
    assert!(bound.effects.is_empty());
    for source in [
        "import socket; s=socket.socket(); c=s; c.close(); s.bind(('127.0.0.1',1234))",
        "import socket; s=socket.socket(); s.accept()",
        "import socket; s=socket.socket(); s.sendall(b'x')",
        "import socket; s=socket.socket(); s.connect(('127.0.0.1',1234))",
        "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)",
        "import socket; s=socket.socket(fileno=3)",
        "import socket; s=socket.socket(); s.bind(('localhost',1234))",
        "import socket; s=socket.socket(); s.bind(('127.0.0.1',1234)); unknown_call()",
        "import socket; s=socket.socket(); s.bind(('127.0.0.1',1234)); s.bind(('0.0.0.0',1234))",
    ] {
        let p = check(source);
        assert!(p.gap.is_some(), "{source}: {p:?}");
        assert!(p.effects.is_empty());
    }
}

#[test]
fn constant_control_and_json_match_cpython() {
    for source in [
        "import json; x=[]\nfor i in range(3):\n    print(i)\nprint(json.dumps({'unicode':'中文😀','list':(True,None,7),'del':'\\x7f'}))",
        "x,y=(1,2)\nassert x!=y\nif x in (1,3):\n    print('yes')\nelse:\n    unknown_call()",
        "if False:\n    unknown_call()\nelse:\n    print('no')",
        "for i in range(4,0,-2):\n    print(i)\nprint(1==True,0 not in (1,2))",
    ] {
        let native = std::process::Command::new("/usr/bin/python3")
            .args(["-I", "-S", "-c", source])
            .output()
            .unwrap();
        assert!(native.status.success(), "{source}: {:?}", native.stderr);
        let p = check(source);
        assert_eq!(p.gap, None, "{source}: {p:?}");
        assert!(p.stdout_complete);
        assert_eq!(p.stdout, native.stdout, "{source}");
    }
}

#[test]
fn control_budgets_and_unsupported_targets_keep_the_program_incomplete() {
    for source in [
        "for i in range(4097):\n    pass",
        "for i in range(3000):\n    print(i)",
        "for i in range(0):\n    pass\nelse:\n    unknown_call()",
        "a,*rest=(1,2,3)",
        "assert False\nprint('unreachable')",
        "a,b=(1,2,3)",
        "import socket\nif socket.socket():\n    pass",
        "print=1\nprint('x')",
        "print(len(range(2)+range(3)))",
        "import json; print(json.dumps(range(3)))",
        "import json; print(json.dumps({1:'one',True:'true'}))",
        "import json\njson.dumps=lambda x:'ok'\nprint(json.dumps({}))",
    ] {
        let p = check(source);
        assert!(p.gap.is_some(), "{source}: {p:?}");
        assert!(p.effects.is_empty());
    }
    let source = (0..100)
        .map(|i| format!("{}if True:\n", " ".repeat(i)))
        .collect::<String>()
        + &format!("{}pass", " ".repeat(100));
    let p = check(&source);
    assert!(p.gap.unwrap().contains("depth"));
}

#[test]
fn ephemeral_bind_matches_cpython_without_inventing_a_port() {
    let source = "import socket,json\ns=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(1)\nprint(json.dumps(s.getsockname()))\ns.close()";
    let native = std::process::Command::new("/usr/bin/python3")
        .args(["-I", "-S", "-c", source])
        .output()
        .unwrap();
    assert!(native.status.success(), "{:?}", native.stderr);
    let address: serde_json::Value = serde_json::from_slice(&native.stdout).unwrap();
    assert_eq!(address[0], "127.0.0.1");
    assert!(address[1].as_u64().unwrap() > 0);
    let p = check(source);
    assert_eq!(p.gap, None, "{p:?}");
    assert_eq!(
        p.effects,
        [E::ListenNetwork {
            host: "127.0.0.1".into(),
            port: 0
        }]
    );
    assert!(!p.stdout_complete);
}

#[test]
fn response_keeps_file_reads_and_extra_effects_are_not_dropped() {
    let p = check(&format!(
        "{LISTENER}from pathlib import Path\nbody=Path('body').read_bytes()\nc,_=s.accept(); c.sendall(body); c.close(); s.close()"
    ));
    assert_eq!(p.gap, None, "{p:?}");
    assert!(p.effects.contains(&E::ReadFile("body".into())));
    assert!(p.effects.contains(&E::RespondNetwork {
        host: "127.0.0.1".into(),
        port: 19317
    }));
    let p = check(&format!(
        "{LISTENER}c,_=s.accept(); c.sendall(b'yes'); unknown_call()"
    ));
    assert!(p.gap.is_some());
    assert!(p.effects.is_empty());
}
