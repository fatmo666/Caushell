use caushell_profile::{PythonEffect as E, PythonInputs, analyze_python};

struct Inputs;
impl PythonInputs for Inputs {
    fn environment(&mut self, name: &str) -> Result<Option<String>, String> {
        if name == "BIND" {
            Ok(Some("127.0.0.2".into()))
        } else {
            Err("unknown environment".into())
        }
    }
    fn file(&mut self, path: &str) -> Result<Vec<u8>, String> {
        if path == "document" {
            Ok(b"bytes".to_vec())
        } else {
            Err("unknown file".into())
        }
    }
}
fn check(source: &str) -> caushell_profile::PythonAnalysis {
    analyze_python(source, &[], &mut Inputs)
}
fn server(methods: &str) -> String {
    format!(
        "from http.server import HTTPServer,BaseHTTPRequestHandler\nfrom pathlib import Path\nbody=Path('document').read_bytes()\nclass Preview(BaseHTTPRequestHandler):\n{methods}\nserver=HTTPServer(('127.0.0.2',19231),Preview)\nserver.timeout=2\nserver.handle_request()\nserver.server_close()"
    )
}

#[test]
fn request_dependent_returns_keep_both_response_paths_and_file_origins() {
    let p = check(&server(
        "    def do_GET(self):\n        if self.path != '/item':\n            self.send_error(404)\n            return\n        self.send_response(200)\n        self.send_header('Content-Length',str(len(body)))\n        self.end_headers()\n        self.wfile.write(body)\n    def log_message(self,*args):\n        pass",
    ));
    assert_eq!(p.gap, None, "{p:?}");
    assert!(p.effects.contains(&E::ReadFile("document".into())));
    assert!(p.effects.contains(&E::ListenNetwork {
        host: "127.0.0.2".into(),
        port: 19231
    }));
    assert!(
        p.effects
            .iter()
            .filter(|e| matches!(e,E::RespondNetwork {host,port:19231} if host=="127.0.0.2"))
            .count()
            >= 2
    );
    assert!(!p.stdout_complete);
}

#[test]
fn handler_closure_uses_the_current_argv_environment_and_bounded_request_loop() {
    let source = "import os,sys\nsys.argv=['preview',os.environ['BIND'],'document']\nfrom http.server import BaseHTTPRequestHandler as Base,HTTPServer as Server\nfrom pathlib import Path\nimport json\nbody=Path(sys.argv[2]).read_bytes()\nclass Handler(Base):\n    def do_GET(this):\n        if this.path != '/data':\n            this.send_error(404)\n            return\n        this.send_response(200)\n        this.send_header('Content-Length',str(len(body)))\n        this.end_headers()\n        this.wfile.write(body)\n    def log_message(this,*args):\n        pass\nservice=Server((sys.argv[1],19235),Handler)\nservice.timeout=3\nprint(json.dumps({'bound':list(service.server_address)}),flush=True)\nfor _ in range(2):\n    service.handle_request()\nservice.server_close()";
    let p = check(source);
    assert_eq!(p.gap, None, "{p:?}");
    assert!(p.effects.contains(&E::ReadFile("document".into())));
    assert!(p.effects.contains(&E::ListenNetwork {
        host: "127.0.0.2".into(),
        port: 19235
    }));
    assert!(!p.stdout_complete);
    let missing = check(&source.replace("['BIND']", "['UNOBSERVED']"));
    assert!(
        missing
            .gap
            .as_deref()
            .is_some_and(|s| s.contains("unknown environment")),
        "{missing:?}"
    );
    assert!(missing.effects.is_empty());
}

#[test]
fn all_dispatched_methods_and_logging_hooks_are_checked() {
    for methods in [
        "    def do_GET(self):\n        self.send_response(200)\n    def do_POST(self):\n        unknown_call()",
        "    def do_GET(self):\n        pass\n    def log_message(self,*args):\n        unknown_call()",
        "    def do_GET(self):\n        if self.path == '/hidden':\n            unknown_call()\n        self.send_error(404)",
        "    def do_GET(self):\n        self.wfile.write(Path(self.path).read_bytes())",
        "    def do_GET(self):\n        self.send_response(200)\n        unknown_call()",
    ] {
        let p = check(&server(methods));
        assert!(p.gap.is_some(), "{methods}: {p:?}");
        assert!(p.effects.is_empty());
    }
}

#[test]
fn unknown_branch_values_are_not_promoted_to_a_known_child_argv() {
    let p=check(&server("    def do_GET(self):\n        if self.path == '/a':\n            name='safe'\n        else:\n            name='other'\n        subprocess.run(['tool',name])").replacen("from pathlib", "import subprocess\nfrom pathlib",1));
    assert!(p.gap.is_some(), "{p:?}");
    assert!(p.effects.is_empty());
    let p = check(&server(
        "    def do_GET(self):\n        if self.path == '/a':\n            name='same'\n        else:\n            name='same'\n        self.send_header('X-Value',name)",
    ));
    assert_eq!(p.gap, None, "{p:?}");
}

#[test]
fn handler_scope_rebinding_and_framework_overrides_stay_explicit() {
    for methods in [
        "    def __init__(self):\n        pass",
        "    def setup(self):\n        pass",
        "    def do_GET(self,x=unknown_call()):\n        pass",
        "    @unknown_decorator\n    def do_GET(self):\n        pass",
        "    async def do_GET(self):\n        pass",
        "    def do_GET(self):\n        self.wfile.write(body)\n        body=b'rebound'",
        "    def do_GET(self):\n        return body\n        body=b'rebound'",
        "    def do_GET(self):\n        if self.path == '/x':\n            body=b'value'\n        return body",
        "    def do_GET(self):\n        print('x')\n        print=unknown_call()",
        "    def do_GET(self):\n        import subprocess\n        subprocess.run(['tool'])",
        "    def do_GET(self):\n        sys.argv=['changed']",
        "    def do_GET(self):\n        server.server_close()",
        "    do_GET=unknown_call()",
    ] {
        let p = check(&server(methods).replacen("from pathlib", "import sys\nfrom pathlib", 1));
        assert!(p.gap.is_some(), "{methods}: {p:?}");
        assert!(p.effects.is_empty());
    }
}

#[test]
fn http_constructor_modes_and_server_lifecycle_are_not_ignored() {
    for tail in [
        "server=HTTPServer(('localhost',19231),Preview)",
        "server=HTTPServer(('127.0.0.1',19231),Preview,bind_and_activate=False)",
        "server=HTTPServer(('127.0.0.1',19231),Preview); server.server_close(); server.handle_request()",
        "server=HTTPServer(('127.0.0.1',19231),Preview); server.serve_forever()",
        "server=HTTPServer(('127.0.0.1',19231),Preview); server.socket=unknown_call()",
    ] {
        let source = format!(
            "from http.server import HTTPServer,BaseHTTPRequestHandler\nclass Preview(BaseHTTPRequestHandler):\n    def do_GET(self):\n        pass\n{tail}"
        );
        assert!(check(&source).gap.is_some(), "{source}");
    }
}

#[test]
fn both_returns_stop_the_method_but_not_other_possible_request_methods() {
    let p = check(&server(
        "    def do_GET(self):\n        if self.path == '/x':\n            self.send_error(404)\n            return\n        else:\n            self.send_error(405)\n            return\n        unknown_unreachable_call()\n    def do_POST(self):\n        self.send_error(501)",
    ));
    assert_eq!(p.gap, None, "{p:?}");
    let p = check(&server(
        "    def do_GET(self):\n        if self.path == '/x':\n            return\n        unknown_reachable_call()",
    ));
    assert!(p.gap.is_some());
}

#[test]
fn http_contract_matches_native_request_paths_and_framework_dispatch() {
    let methods = "    def do_GET(self):\n        if self.path != '/item':\n            self.send_error(404)\n            return\n        self.send_response(200)\n        self.send_header('Content-Length',str(len(body)))\n        self.end_headers()\n        self.wfile.write(body)\n    def log_message(self,*args):\n        pass";
    let definition = format!(
        "from http.server import HTTPServer,BaseHTTPRequestHandler\nbody=b'bytes'\nclass Handler(BaseHTTPRequestHandler):\n{methods}\nserver=HTTPServer(('127.0.0.1',0),Handler)\nserver.timeout=3\n"
    );
    let modeled = check(&format!(
        "{definition}for _ in range(3):\n    server.handle_request()\nserver.server_close()"
    ));
    assert_eq!(modeled.gap, None, "{modeled:?}");
    assert!(modeled.effects.contains(&E::ListenNetwork {
        host: "127.0.0.1".into(),
        port: 0
    }));
    assert!(
        modeled
            .effects
            .iter()
            .any(|e| matches!(e, E::RespondNetwork { port: 0, .. }))
    );
    let native = format!(
        "{definition}\nimport http.client,threading\nobserved=[]\ndef client():\n    for method,path in [('GET','/item'),('GET','/missing'),('POST','/item')]:\n        connection=http.client.HTTPConnection(*server.server_address,timeout=3)\n        connection.request(method,path)\n        response=connection.getresponse()\n        observed.append((response.status,response.read()))\n        connection.close()\nthread=threading.Thread(target=client,daemon=True)\nthread.start()\nfor _ in range(3):\n    server.handle_request()\nserver.server_close()\nthread.join(4)\nassert not thread.is_alive()\nassert [r[0] for r in observed]==[200,404,501],observed\nassert observed[0][1]==body,observed\n"
    );
    let output = std::process::Command::new("/usr/bin/python3")
        .args(["-I", "-S", "-c", &native])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}
