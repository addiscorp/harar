//! A real `harar serve` for integration tests, driven with the CLI.
#![allow(dead_code)] // each test crate uses a different part of this

use age::secrecy::ExposeSecret;
use harar_client::Jwks;
use harar_client::oidc;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const AUD: &str = "https://api.example.test";
pub const GILD: &str = "https://gild.example.test";

pub struct Issuer {
    child: Child,
    pub socket: PathBuf,
    pub address: String,
    pub url: String,
    _dir: tempfile::TempDir,
}

impl Drop for Issuer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Issuer {
    pub fn start() -> Self {
        let dir = tempfile::Builder::new().prefix("hi").tempdir().unwrap();
        let state = dir.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let key = dir.path().join("master.key");
        fs::write(&key, age::x25519::Identity::generate().to_string().expose_secret()).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o400)).unwrap();
        fs::write(dir.path().join("replication-token"), "test-replication-token\n").unwrap();
        Self::spawn(dir)
    }

    /// Stops this issuer and starts another on the same state.
    pub fn restart(mut self) -> Self {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.socket);
        let dir = std::mem::replace(&mut self._dir, tempfile::tempdir().unwrap());
        Self::spawn(dir)
    }

    fn spawn(dir: tempfile::TempDir) -> Self {
        let state = dir.path().join("state");
        let key = dir.path().join("master.key");
        let replication = dir.path().join("replication-token");
        let socket = dir.path().join("harar.sock");
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let address = format!("127.0.0.1:{port}");
        let url = format!("http://{address}");
        let path = |p: PathBuf| p.to_str().unwrap().to_string();
        let child = Command::new(env!("CARGO_BIN_EXE_harar"))
            .arg("serve")
            .args(["--socket", &path(socket.clone())])
            .args(["--state-path", &path(state.join("keys.age"))])
            .args(["--audit-log", &path(dir.path().join("audit.log"))])
            .args(["--replication-token-file", &path(replication)])
            .args(["--signing-key-file", &path(state.join("signing.key"))])
            .args(["--issuer", &url, "--public-listen", &address])
            .env("GILD_VAULT_MASTER_KEY_PATH", &key)
            .stdout(Stdio::null())
            .stderr(fs::File::create(dir.path().join("serve.log")).unwrap())
            .spawn()
            .expect("spawn harar serve");
        // Generous: macOS scans a freshly built binary on its first runs.
        let deadline = Instant::now() + Duration::from_secs(30);
        while std::os::unix::net::UnixStream::connect(&socket).is_err() || TcpStream::connect(&address).is_err() {
            let log = fs::read_to_string(dir.path().join("serve.log")).unwrap_or_default();
            assert!(Instant::now() < deadline, "harar serve did not start: {log}");
            std::thread::sleep(Duration::from_millis(25));
        }
        Issuer { child, socket, address, url, _dir: dir }
    }

    pub fn harar(&self, args: &[&str]) -> Output {
        self.harar_with(args, &[])
    }

    pub fn harar_with(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_harar"))
            .args(args)
            .envs(env.iter().copied())
            .env("HARAR_SOCKET", &self.socket)
            .output()
            .expect("run harar")
    }

    pub fn ok(&self, args: &[&str]) -> serde_json::Value {
        self.ok_with(args, &[])
    }

    pub fn ok_with(&self, args: &[&str], env: &[(&str, &str)]) -> serde_json::Value {
        let out = self.harar_with(args, env);
        assert!(out.status.success(), "harar {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        serde_json::from_slice(&out.stdout).unwrap()
    }

    /// A plain HTTP request to the public listener: (status, body).
    pub fn http(&self, method: &str, path: &str) -> (u16, serde_json::Value) {
        let mut stream = TcpStream::connect(&self.address).unwrap();
        write!(stream, "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", self.address).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
        (status, serde_json::from_str(body).unwrap())
    }

    pub fn jwks(&self) -> Jwks {
        let (status, discovery) = self.http("GET", oidc::DISCOVERY_PATH);
        assert_eq!(status, 200);
        assert_eq!(discovery["issuer"], self.url);
        let jwks_uri = discovery["jwks_uri"].as_str().unwrap();
        let path = jwks_uri.strip_prefix(&self.url).unwrap();
        let (status, jwks) = self.http("GET", path);
        assert_eq!(status, 200);
        serde_json::from_value(jwks).unwrap()
    }
}

pub fn me() -> String {
    let out = Command::new("id").arg("-un").output().unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub fn grant_me(issuer: &Issuer) {
    issuer.ok(&["workload", "add", "svc:ci@test", "--user", &me(), "--sessions-for", "agent:*"]);
    issuer.ok(&["policy", "allow", "svc:ci@test", "--aud", AUD, "--scope", "deploy:*", "--may-act-for", "agent:*"]);
    issuer.ok(&["policy", "allow", "svc:ci@test", "--aud", GILD, "--scope", "repo:*", "--may-act-for", "agent:*"]);
}

/// Ava's session, for Sami: deploy to staging, and anything in repos.
pub fn start_ava(issuer: &Issuer) -> (String, String) {
    let started = issuer.ok(&[
        "session", "start", "agent:ava", "--for", "user:sami",
        "--grant", &format!("{AUD}=deploy:staging"), "--grant", &format!("{GILD}=repo:*"),
    ]);
    let sid = started["session"]["sid"].as_str().unwrap().to_string();
    (sid, started["session_token"].as_str().unwrap().to_string())
}

pub fn refused_with(out: Output, reason: &str) {
    assert!(!out.status.success(), "allowed, expected {reason}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(reason), "expected {reason}: {stderr}");
}

