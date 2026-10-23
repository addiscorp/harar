//! Scenario S2 B/C and S10 end to end: a real issuer, a real `harar broker
//! serve`, and a fake upstream that records exactly what reached it. The agent
//! side only ever holds a placeholder.

mod common;

use common::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const REAL_KEY: &str = "sk-upstream-real-key-0123";

/// Answers every request with 200 and keeps the raw requests it got.
struct Upstream {
    url: String,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Upstream {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut reader = BufReader::new(stream);
                let mut head = String::new();
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap_or(0);
                    }
                    head.push_str(&line);
                }
                let mut body = vec![0; length];
                let _ = reader.read_exact(&mut body);
                record.lock().unwrap().push(format!("{head}\r\n{}", String::from_utf8_lossy(&body)));
                let reply = r#"{"id":"msg_1","content":"hello from upstream"}"#;
                let mut stream = reader.into_inner();
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nx-upstream: yes\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                    reply.len()
                );
            }
        });
        Upstream { url, seen }
    }

    fn requests(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

struct BrokerProcess {
    child: Child,
    address: String,
}

impl Drop for BrokerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_broker(issuer: &Issuer, audit_log: &std::path::Path) -> BrokerProcess {
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let address = format!("127.0.0.1:{port}");
    let child = Command::new(env!("CARGO_BIN_EXE_harar"))
        .args(["broker", "serve", "--listen", &address, "--audit-log", audit_log.to_str().unwrap()])
        .env("HARAR_SOCKET", &issuer.socket)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn harar broker");
    // Hold it first, so a failed start below still stops the broker.
    let broker = BrokerProcess { child, address };
    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(&broker.address).is_err() {
        assert!(Instant::now() < deadline, "harar broker did not start");
        std::thread::sleep(Duration::from_millis(25));
    }
    broker
}

/// What an SDK in the VM sends: POST with the placeholder as its API key.
fn call(broker: &BrokerProcess, path: &str, key: Option<&str>) -> (u16, String) {
    let body = r#"{"model":"m","messages":[]}"#;
    let mut stream = TcpStream::connect(&broker.address).unwrap();
    let key_header = key.map(|k| format!("x-api-key: {k}\r\n")).unwrap_or_default();
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: {}\r\n{key_header}content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        broker.address,
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let status = response.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, response)
}

fn set_up(issuer: &Issuer, upstream: &Upstream) -> (String, String, String) {
    grant_me(issuer);
    issuer.ok_with(&["put", "dev/fake/key", "--secret-env", "REAL"], &[("REAL", REAL_KEY)]);
    issuer.ok(&[
        "broker", "service", "add", "fake", "--upstream", &upstream.url, "--header", "x-api-key", "--secret", "dev/fake/key",
    ]);
    // The broker runs as this test's OS user, which is the svc:ci@test workload.
    issuer.ok(&["broker", "trust", "svc:ci@test"]);
    let (sid, session_token) = start_ava(issuer);
    let out = issuer.harar(&["broker", "placeholder", "fake", "--session", &sid]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let placeholder = String::from_utf8(out.stdout).unwrap().trim().to_string();
    assert!(placeholder.starts_with("harar-ph-"));
    (sid, session_token, placeholder)
}

#[test]
fn the_vm_holds_a_placeholder_and_the_upstream_gets_the_real_key() {
    let issuer = Issuer::start();
    let upstream = Upstream::start();
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("broker.log");
    let (sid, session_token, placeholder) = set_up(&issuer, &upstream);
    let broker = start_broker(&issuer, &audit);

    // S2 C: not granted yet. Nothing reaches the upstream.
    let (status, body) = call(&broker, "/fake/v1/messages?beta=1", Some(&placeholder));
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("not_granted"));
    assert!(upstream.requests().is_empty());

    let asked = issuer.ok_with(
        &["request", "fake", "--reason", "run eval suite", "--secret-env", "AVA"],
        &[("AVA", session_token.as_str())],
    );
    let id = asked["id"].as_str().unwrap();
    let pending = issuer.ok(&["approvals", "list"]);
    assert_eq!(pending[0]["reason"], "run eval suite");
    assert_eq!(pending[0]["sub"], "agent:ava");
    issuer.ok(&["approvals", "approve", id, "--for", "10m"]);

    let (status, body) = call(&broker, "/fake/v1/messages?beta=1", Some(&placeholder));
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("hello from upstream"));
    assert!(body.to_ascii_lowercase().contains("x-upstream: yes"));
    let seen = upstream.requests();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    assert!(request.starts_with("POST /v1/messages?beta=1 HTTP/1.1"), "{request}");
    assert!(request.to_ascii_lowercase().contains(&format!("x-api-key: {REAL_KEY}")), "{request}");
    assert!(!request.contains("harar-ph-"), "the placeholder leaked upstream: {request}");
    assert!(request.ends_with(r#"{"model":"m","messages":[]}"#));

    // S10: revoke the session; the very next call is refused.
    issuer.ok(&["session", "revoke", &sid]);
    let (status, body) = call(&broker, "/fake/v1/messages", Some(&placeholder));
    assert_eq!(status, 403);
    assert!(body.contains("session_not_live"));
    assert_eq!(upstream.requests().len(), 1);

    let log = std::fs::read_to_string(&audit).unwrap();
    assert!(log.contains(&sid), "the audit names the session");
    assert!(!log.contains(REAL_KEY) && !log.contains(&placeholder), "the audit holds no secrets");
    assert_eq!(log.lines().count(), 3);
}

#[test]
fn only_granted_placeholders_for_that_service_get_through() {
    let issuer = Issuer::start();
    let upstream = Upstream::start();
    let dir = tempfile::tempdir().unwrap();
    let (_, _, placeholder) = set_up(&issuer, &upstream);
    issuer.ok(&["broker", "allow", "fake", "--to", "agent:*"]);
    let broker = start_broker(&issuer, &dir.path().join("broker.log"));

    assert_eq!(call(&broker, "/fake/v1/x", Some(&placeholder)).0, 200);
    assert_eq!(call(&broker, "/fake/v1/x", None).0, 401);
    assert_eq!(call(&broker, "/fake/v1/x", Some("harar-ph-guessed")).0, 403);
    assert_eq!(call(&broker, "/fake/v1/x", Some(REAL_KEY)).0, 401, "a real-looking key is not a placeholder");
    let (status, body) = call(&broker, "/other/v1/x", Some(&placeholder));
    assert_eq!(status, 403);
    assert!(body.contains("wrong_service"));
    assert_eq!(upstream.requests().len(), 1);

    issuer.ok(&["broker", "disallow", "fake", "--to", "agent:*"]);
    assert_eq!(call(&broker, "/fake/v1/x", Some(&placeholder)).0, 403);
}

#[test]
fn only_trusted_brokers_may_resolve() {
    let issuer = Issuer::start();
    let upstream = Upstream::start();
    let dir = tempfile::tempdir().unwrap();
    grant_me(&issuer);
    issuer.ok_with(&["put", "dev/fake/key", "--secret-env", "REAL"], &[("REAL", REAL_KEY)]);
    issuer.ok(&["broker", "service", "add", "fake", "--upstream", &upstream.url, "--header", "x-api-key", "--secret", "dev/fake/key"]);
    issuer.ok(&["broker", "allow", "fake", "--to", "agent:*"]);
    let (sid, _) = start_ava(&issuer);
    let out = issuer.harar(&["broker", "placeholder", "fake", "--session", &sid]);
    let placeholder = String::from_utf8(out.stdout).unwrap().trim().to_string();
    let broker = start_broker(&issuer, &dir.path().join("broker.log"));

    let (status, body) = call(&broker, "/fake/v1/x", Some(&placeholder));
    assert_eq!(status, 403);
    assert!(body.contains("not_a_broker"));
    assert!(upstream.requests().is_empty());
}
