//! Starts a real `harar serve` as a new primary owned by whoever runs the
//! test, drives it with the CLI, and checks its tokens the way a receiver
//! would: by fetching the discovery document and JWKS over HTTP.

use age::secrecy::ExposeSecret;
use harar_client::Jwks;
use harar_client::oidc::{self, IdentityClaims};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const AUD: &str = "https://api.example.test";
const OWNER: &str = "gg.addis.human.owner";

struct Primary {
    child: Child,
    socket: PathBuf,
    address: String,
    url: String,
    /// More `harar serve` flags, kept for a restart.
    extra: Vec<String>,
    _dir: tempfile::TempDir,
}

impl Drop for Primary {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Primary {
    fn start() -> Self {
        Self::start_with(vec![])
    }

    fn start_with(extra: Vec<String>) -> Self {
        let dir = tempfile::Builder::new().prefix("hp").tempdir().unwrap();
        let state = dir.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let key = dir.path().join("master.key");
        fs::write(&key, age::x25519::Identity::generate().to_string().expose_secret()).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o400)).unwrap();
        Self::spawn(dir, extra)
    }

    /// Stops this primary and starts another on the same state.
    fn restart(mut self) -> Self {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.socket);
        let dir = std::mem::replace(&mut self._dir, tempfile::tempdir().unwrap());
        Self::spawn(dir, std::mem::take(&mut self.extra))
    }

    fn spawn(dir: tempfile::TempDir, extra: Vec<String>) -> Self {
        let state = dir.path().join("state");
        let socket = dir.path().join("harar.sock");
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let address = format!("127.0.0.1:{port}");
        let url = format!("http://{address}");
        let path = |p: PathBuf| p.to_str().unwrap().to_string();
        let child = Command::new(env!("CARGO_BIN_EXE_harar"))
            .arg("serve")
            .args(["--socket", &path(socket.clone())])
            .args(["--org", "gg.addis", "--machine", "testbox", "--owner", OWNER, "--owner-user", &me()])
            .args(["--state-path", &path(state.join("keys.age"))])
            .args(["--audit-log", &path(dir.path().join("audit.log"))])
            .args(["--signing-key-file", &path(state.join("signing.key"))])
            .args(["--issuer", &url, "--public-listen", &address])
            .args(&extra)
            .args(["--master-key-file", &path(dir.path().join("master.key"))])
            .stdout(Stdio::null())
            .stderr(fs::File::create(dir.path().join("serve.log")).unwrap())
            .spawn()
            .expect("spawn harar serve");
        // Hold it first, so a failed start below still stops it.
        let primary = Primary { child, socket, address, url, extra, _dir: dir };
        // Generous: macOS scans a freshly built binary on its first runs.
        let deadline = Instant::now() + Duration::from_secs(30);
        while std::os::unix::net::UnixStream::connect(&primary.socket).is_err() || TcpStream::connect(&primary.address).is_err() {
            let log = fs::read_to_string(primary._dir.path().join("serve.log")).unwrap_or_default();
            assert!(Instant::now() < deadline, "harar serve did not start: {log}");
            std::thread::sleep(Duration::from_millis(25));
        }
        primary
    }

    fn harar(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_harar")).args(args).env("HARAR_SOCKET", &self.socket).output().expect("run harar")
    }

    fn ok(&self, args: &[&str]) -> serde_json::Value {
        let out = self.harar(args);
        assert!(out.status.success(), "harar {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn refused(&self, args: &[&str], reason: &str) {
        let out = self.harar(args);
        assert!(!out.status.success(), "{args:?} was allowed");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(reason), "{args:?}: {stderr}");
    }

    /// A plain HTTP request to the public listener: (status, body).
    fn http(&self, method: &str, path: &str) -> (u16, serde_json::Value) {
        let mut stream = TcpStream::connect(&self.address).unwrap();
        write!(stream, "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", self.address).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
        (status, serde_json::from_str(body).unwrap())
    }

    fn jwks(&self) -> Jwks {
        let (status, discovery) = self.http("GET", oidc::DISCOVERY_PATH);
        assert_eq!(status, 200);
        assert_eq!(discovery["issuer"], self.url);
        let jwks_uri = discovery["jwks_uri"].as_str().unwrap();
        let (status, jwks) = self.http("GET", jwks_uri.strip_prefix(&self.url).unwrap());
        assert_eq!(status, 200);
        serde_json::from_value(jwks).unwrap()
    }
}

fn me() -> String {
    let out = Command::new("id").arg("-un").output().unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[test]
fn tokens_verify_against_the_published_discovery_and_jwks() {
    let primary = Primary::start();
    let jwks = primary.jwks();
    assert_eq!(jwks.keys.iter().map(|k| k.alg.as_str()).collect::<Vec<_>>(), ["ES256", "EdDSA"]);
    for alg in ["ES256", "EdDSA"] {
        let out = primary.ok(&["token", "--aud", AUD, "--scope", "deploy:staging", "--alg", alg]);
        let claims: IdentityClaims = oidc::verify_identity(&jwks, out["token"].as_str().unwrap(), &primary.url, AUD, now()).unwrap();
        assert_eq!(claims.sub, OWNER, "the subject comes from the calling OS user");
        assert_eq!(claims.extra["zone"], "gg.addis.zone.testbox");
        assert_eq!(claims.extra["via"], "gg.addis.broker.testbox");
        assert!(claims.has_scope("deploy:staging"));
        assert_eq!(claims.exp - claims.iat, oidc::DEFAULT_TTL_SECONDS);
        assert_eq!(serde_json::to_value(&claims).unwrap(), out["claims"]);
    }
    let raw = primary.harar(&["token", "--aud", AUD, "--ttl", "1h", "--raw"]);
    assert!(raw.status.success());
    let claims = oidc::verify_identity(&jwks, String::from_utf8(raw.stdout).unwrap().trim(), &primary.url, AUD, now()).unwrap();
    assert_eq!(claims.exp - claims.iat, 3600);
    primary.refused(&["token", "--aud", AUD, "--ttl", "61m"], "token_refused");
}

#[test]
fn secrets_and_policy_through_the_cli() {
    let primary = Primary::start();
    let mut put = Command::new(env!("CARGO_BIN_EXE_harar"));
    put.args(["put", "prod/site/DATABASE_URL", "--secret-stdin"]).env("HARAR_SOCKET", &primary.socket).stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut child = put.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"postgres://site\n").unwrap();
    assert!(child.wait_with_output().unwrap().status.success());
    assert_eq!(primary.ok(&["get", "prod/site/DATABASE_URL"])["value"], "postgres://site");

    primary.ok(&["policy", "role", "set", "gg.addis.role.site", "--read", "prod/site/*", "--token", &format!("{AUD} deploy:site")]);
    primary.ok(&["policy", "bind", "gg.addis.service.site", "--role", "gg.addis.role.site", "--zone", "gg.addis.zone.testbox"]);
    let shown = primary.ok(&["policy", "show"]);
    assert_eq!(shown["users"][me()], OWNER);
    assert_eq!(shown["policy"]["bindings"].as_array().unwrap().len(), 2);

    let test = |args: &[&str]| primary.ok(&[&["policy", "test", "--actor", "gg.addis.service.site"][..], args].concat())["decision"].as_str().unwrap().to_string();
    assert_eq!(test(&["--read", "prod/site/DATABASE_URL"]), "allow by gg.addis.role.site");
    assert_eq!(test(&["--read", "prod/billing/KEY"]), "no_binding");
    assert_eq!(test(&["--token", &format!("{AUD} deploy:site")]), "allow by gg.addis.role.site");
    assert_eq!(test(&["--token", &format!("{AUD} admin")]), "no_binding");

    primary.refused(&["policy", "user", "unmap", &me()], "would_lock_out");
    primary.refused(&["get", "harar:policy"], "reserved_key");
}

#[test]
fn the_public_listener_serves_only_discovery_and_keys() {
    let primary = Primary::start();
    assert_eq!(primary.http("GET", "/v1/secret/prod/site/DATABASE_URL").0, 404);
    assert_eq!(primary.http("POST", oidc::JWKS_PATH).0, 405);
    assert_eq!(primary.http("GET", oidc::JWKS_PATH).0, 200);
    assert_eq!(primary.http("GET", oidc::DISCOVERY_PATH).0, 200);
}

#[test]
fn keys_secrets_and_policy_survive_a_restart() {
    let primary = Primary::start();
    primary.ok(&["policy", "role", "set", "gg.addis.role.kept", "--read", "kept/*"]);
    let before = primary.jwks();
    let primary = primary.restart();
    assert_eq!(primary.jwks(), before, "the signing keys were read back, not regenerated");
    let roles = primary.ok(&["policy", "show"])["policy"]["roles"].clone();
    assert!(roles.as_array().unwrap().iter().any(|role| role["name"] == "gg.addis.role.kept"));
    let token = primary.ok(&["token", "--aud", AUD]);
    assert!(oidc::verify_identity(&before, token["token"].as_str().unwrap(), &primary.url, AUD, now()).is_ok());
}

/// Runs one statement against the test database and returns every bytea and
/// text cell it produced, as bytes.
fn sql(url: &str, statement: &str) -> Vec<Vec<u8>> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls).await.unwrap();
        tokio::spawn(connection);
        let mut cells = Vec::new();
        for message in client.simple_query(statement).await.unwrap() {
            if let tokio_postgres::SimpleQueryMessage::Row(row) = message {
                cells.extend((0..row.len()).filter_map(|i| row.get(i).map(|cell| cell.as_bytes().to_vec())));
            }
        }
        cells
    })
}

#[test]
fn a_postgres_primary_keeps_secrets_and_policy_encrypted_across_a_restart() {
    let Ok(url) = std::env::var("HARAR_TEST_DATABASE_URL") else {
        assert!(std::env::var_os("HARAR_TEST_NO_POSTGRES").is_some(), "set HARAR_TEST_DATABASE_URL to a disposable Postgres, or HARAR_TEST_NO_POSTGRES=1 where there is none");
        eprintln!("SKIPPED: no Postgres on this machine (HARAR_TEST_NO_POSTGRES)");
        return;
    };
    // The primary's schema has a fixed name; the test database is disposable.
    sql(&url, "DROP SCHEMA IF EXISTS harar_primary CASCADE");
    let conninfo = tempfile::Builder::new().prefix("hpg").tempdir().unwrap();
    let file = conninfo.path().join("postgres");
    fs::write(&file, &url).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let primary = Primary::start_with(vec!["--postgres-file".into(), file.to_str().unwrap().into()]);
    let mut put = Command::new(env!("CARGO_BIN_EXE_harar"));
    put.args(["put", "prod/site/DATABASE_URL", "--secret-stdin"]).env("HARAR_SOCKET", &primary.socket).stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut child = put.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"postgres://plaintext-marker\n").unwrap();
    assert!(child.wait_with_output().unwrap().status.success());
    primary.ok(&["policy", "role", "set", "gg.addis.role.kept", "--read", "kept/*"]);

    let primary = primary.restart();
    assert_eq!(primary.ok(&["get", "prod/site/DATABASE_URL"])["value"], "postgres://plaintext-marker");
    let roles = primary.ok(&["policy", "show"])["policy"]["roles"].clone();
    assert!(roles.as_array().unwrap().iter().any(|role| role["name"] == "gg.addis.role.kept"));

    let paths = sql(&url, "SELECT path FROM harar_primary.secrets");
    assert!(paths.contains(&b"prod/site/DATABASE_URL".to_vec()) && paths.contains(&b"harar:policy".to_vec()), "both live in Postgres");
    let stored = sql(&url, "SELECT encode(ciphertext, 'escape') FROM harar_primary.secrets").concat();
    for plaintext in [&b"plaintext-marker"[..], b"gg.addis.role.kept", b"gg.addis.human.owner"] {
        assert!(!stored.windows(plaintext.len()).any(|w| w == plaintext), "{} is stored in the clear", String::from_utf8_lossy(plaintext));
    }
}

/// Runs a `harar serve` that must refuse to start, and returns what it said.
/// One that starts anyway is stopped and fails the test, rather than hanging it.
fn refused_to_start(command: &mut Command) -> String {
    let log = tempfile::NamedTempFile::new().unwrap();
    let mut child = command.stdout(Stdio::null()).stderr(log.reopen().unwrap()).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("a second primary started: {}", fs::read_to_string(log.path()).unwrap_or_default());
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    assert!(!status.success());
    fs::read_to_string(log.path()).unwrap()
}

#[test]
fn a_second_primary_on_the_same_state_refuses_to_start() {
    let primary = Primary::start();
    let dir = primary._dir.path();
    let state = dir.join("state");
    let serve = |socket: &Path, state: &Path, audit: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_harar"));
        command
            .arg("serve")
            .args(["--socket", socket.to_str().unwrap(), "--org", "gg.addis", "--machine", "testbox", "--owner", OWNER])
            .args(["--state-path", state.join("keys.age").to_str().unwrap()])
            .args(["--audit-log", dir.join(audit).to_str().unwrap()])
            .args(["--signing-key-file", state.join("signing.key").to_str().unwrap()])
            .args(["--master-key-file", dir.join("master.key").to_str().unwrap()]);
        command
    };
    let said = refused_to_start(&mut serve(&dir.join("other.sock"), &state, "audit.log"));
    assert!(said.contains("another harar primary is using this state folder"), "{said}");
    // Nor may anything take over a socket a live primary serves.
    let said = refused_to_start(&mut serve(&primary.socket, &dir.join("state2"), "audit2.log"));
    assert!(said.contains("another harar is serving"), "{said}");
    assert_eq!(primary.ok(&["policy", "show"])["users"][me()], OWNER, "the first one still answers");
}
