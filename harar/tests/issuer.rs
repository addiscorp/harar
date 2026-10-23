//! Starts a real `harar serve` as an OIDC issuer, sets up a workload and a
//! grant with the CLI, then checks its tokens the way a receiver would: by
//! fetching the discovery document and JWKS over HTTP.

use age::secrecy::ExposeSecret;
use harar_client::Jwks;
use harar_client::oidc::{self, IdentityClaims};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const AUD: &str = "https://api.example.test";
const GILD: &str = "https://gild.example.test";

struct Issuer {
    child: Child,
    socket: PathBuf,
    address: String,
    url: String,
    _dir: tempfile::TempDir,
}

impl Drop for Issuer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Issuer {
    fn start() -> Self {
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
    fn restart(mut self) -> Self {
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

    fn harar(&self, args: &[&str]) -> Output {
        self.harar_with(args, &[])
    }

    fn harar_with(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_harar"))
            .args(args)
            .envs(env.iter().copied())
            .env("HARAR_SOCKET", &self.socket)
            .output()
            .expect("run harar")
    }

    fn ok(&self, args: &[&str]) -> serde_json::Value {
        self.ok_with(args, &[])
    }

    fn ok_with(&self, args: &[&str], env: &[(&str, &str)]) -> serde_json::Value {
        let out = self.harar_with(args, env);
        assert!(out.status.success(), "harar {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        serde_json::from_slice(&out.stdout).unwrap()
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
        let path = jwks_uri.strip_prefix(&self.url).unwrap();
        let (status, jwks) = self.http("GET", path);
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

fn grant_me(issuer: &Issuer) {
    issuer.ok(&["workload", "add", "svc:ci@test", "--user", &me(), "--sessions-for", "agent:*"]);
    issuer.ok(&["policy", "allow", "svc:ci@test", "--aud", AUD, "--scope", "deploy:*", "--may-act-for", "agent:*"]);
    issuer.ok(&["policy", "allow", "svc:ci@test", "--aud", GILD, "--scope", "repo:*", "--may-act-for", "agent:*"]);
}

/// Ava's session, for Sami: deploy to staging, and anything in repos.
fn start_ava(issuer: &Issuer) -> (String, String) {
    let started = issuer.ok(&[
        "session", "start", "agent:ava", "--for", "user:sami",
        "--grant", &format!("{AUD}=deploy:staging"), "--grant", &format!("{GILD}=repo:*"),
    ]);
    let sid = started["session"]["sid"].as_str().unwrap().to_string();
    (sid, started["session_token"].as_str().unwrap().to_string())
}

fn refused_with(out: Output, reason: &str) {
    assert!(!out.status.success(), "allowed, expected {reason}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(reason), "expected {reason}: {stderr}");
}

#[test]
fn tokens_verify_against_the_published_discovery_and_jwks() {
    let issuer = Issuer::start();
    grant_me(&issuer);
    let jwks = issuer.jwks();
    assert_eq!(jwks.keys.iter().map(|k| k.alg.as_str()).collect::<Vec<_>>(), ["ES256", "EdDSA"]);

    let (sid, _) = start_ava(&issuer);
    for alg in ["ES256", "EdDSA"] {
        let out = issuer.ok(&[
            "token", "--aud", AUD, "--scope", "deploy:staging", "--act", "agent:ava", "--session", &sid, "--alg", alg,
        ]);
        let token = out["token"].as_str().unwrap();
        let claims: IdentityClaims = oidc::verify_identity(&jwks, token, &issuer.url, AUD, now()).unwrap();
        assert_eq!(claims.sub, "svc:ci@test", "the subject comes from the calling OS user");
        assert!(claims.has_scope("deploy:staging"));
        assert_eq!(claims.act.as_ref().unwrap().sid.as_deref(), Some(sid.as_str()));
        assert_eq!(claims.act.as_ref().unwrap().chain(), ["agent:ava", "user:sami"], "gild for ava for sami");
        assert_eq!(claims.exp - claims.iat, oidc::DEFAULT_TTL_SECONDS);
        assert_eq!(serde_json::to_value(&claims).unwrap(), out["claims"]);
    }

    let raw = issuer.harar(&["token", "--aud", AUD, "--ttl", "1h", "--raw"]);
    assert!(raw.status.success());
    let token = String::from_utf8(raw.stdout).unwrap();
    let claims = oidc::verify_identity(&jwks, token.trim(), &issuer.url, AUD, now()).unwrap();
    assert_eq!(claims.exp - claims.iat, 3600);
}

#[test]
fn the_issuer_refuses_what_was_not_granted() {
    let issuer = Issuer::start();
    let refused = |args: &[&str], reason: &str| {
        let out = issuer.harar(args);
        assert!(!out.status.success(), "{args:?} was allowed");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(reason), "{args:?}: {stderr}");
    };
    refused(&["token", "--aud", AUD], "not_a_workload");
    grant_me(&issuer);
    refused(&["token", "--aud", "https://other.example.test"], "audience_not_granted");
    refused(&["token", "--aud", AUD, "--scope", "admin:all"], "scope_not_granted");
    refused(&["token", "--aud", AUD, "--act", "user:sami"], "act_not_granted");
    refused(&["token", "--aud", AUD, "--ttl", "61m"], "ttl_out_of_bounds");

    let test = issuer.ok(&["policy", "test", &me(), "--aud", AUD, "--scope", "deploy:prod"]);
    assert_eq!(test["allowed"], true);
    assert_eq!(test["sub"], "svc:ci@test");
    let test = issuer.ok(&["policy", "test", "someone-else", "--aud", AUD]);
    assert_eq!(test["reason"], "not_a_workload");

    issuer.ok(&["policy", "remove", "svc:ci@test", "--aud", AUD]);
    refused(&["token", "--aud", AUD], "audience_not_granted");
    issuer.ok(&["workload", "remove", "svc:ci@test"]);
    refused(&["token", "--aud", AUD], "not_a_workload");
}

#[test]
fn the_public_listener_serves_only_discovery_and_keys() {
    let issuer = Issuer::start();
    issuer.ok(&["workload", "add", "svc:ci@test", "--user", &me()]);
    let listed = issuer.ok(&["workload", "list"]);
    assert_eq!(listed[0]["sub"], "svc:ci@test");

    // Over the socket, the vault answers this; over TCP, nothing does.
    assert_eq!(issuer.http("GET", "/v1/secret/harar:identity").0, 404);
    assert_eq!(issuer.http("POST", oidc::JWKS_PATH).0, 405);
    assert_eq!(issuer.http("GET", "/replication/snapshot").0, 404);
    assert_eq!(issuer.http("GET", oidc::JWKS_PATH).0, 200);
}

#[test]
fn keys_and_rules_survive_a_restart() {
    let issuer = Issuer::start();
    grant_me(&issuer);
    let before = issuer.jwks();
    let issuer = issuer.restart();
    assert_eq!(issuer.jwks(), before, "the signing keys were read back, not regenerated");
    let token = issuer.ok(&["token", "--aud", AUD, "--scope", "deploy:staging"]);
    assert!(oidc::verify_identity(&before, token["token"].as_str().unwrap(), &issuer.url, AUD, now()).is_ok());
}

/// S1 and S7: gild acts for Ava within her session; Ava hands a sub-agent a
/// narrower token; S10: revoking Ava's session ends the sub-agent's too.
#[test]
fn sessions_narrow_through_exchange_and_die_together() {
    let issuer = Issuer::start();
    grant_me(&issuer);
    let jwks = issuer.jwks();
    let (sid, ava_token) = start_ava(&issuer);

    // gild's own grant covers deploy:*, but Ava's session only staging.
    refused_with(
        issuer.harar(&["token", "--aud", AUD, "--scope", "deploy:production", "--act", "agent:ava", "--session", &sid]),
        "scope_not_in_session",
    );
    refused_with(issuer.harar(&["token", "--aud", AUD, "--act", "agent:ava"]), "session_required");
    refused_with(
        issuer.harar(&["token", "--aud", AUD, "--act", "agent:ava", "--session", "s_made_up"]),
        "session_not_live",
    );

    // Ava's session token is for the issuer itself, so no service accepts it.
    let session_claims = oidc::verify_identity(&jwks, &ava_token, &issuer.url, &issuer.url, now()).unwrap();
    assert_eq!(session_claims.sub, "agent:ava");
    assert!(oidc::verify_identity(&jwks, &ava_token, &issuer.url, AUD, now()).is_err());

    let ava = [("AVA_SESSION", ava_token.as_str())];
    let child = issuer.ok_with(
        &["exchange", "--secret-env", "AVA_SESSION", "--name", "reviewer", "--aud", GILD, "--scope", "repo:read", "--ttl", "30m"],
        &ava,
    );
    let claims = oidc::verify_identity(&jwks, child["token"].as_str().unwrap(), &issuer.url, GILD, now()).unwrap();
    assert_eq!(claims.sub, "agent:ava/reviewer");
    assert_eq!(claims.scope, "repo:read");
    assert_eq!(claims.exp - claims.iat, 1800);
    assert_eq!(claims.act.unwrap().chain(), ["agent:ava", "user:sami"]);
    let child_sid = child["session"]["sid"].as_str().unwrap().to_string();
    let child_token = child["session_token"].as_str().unwrap().to_string();
    let reviewer = [("CHILD_SESSION", child_token.as_str())];

    // Never wider than the parent.
    refused_with(
        issuer.harar_with(&["exchange", "--secret-env", "CHILD_SESSION", "--name", "x", "--aud", GILD, "--scope", "repo:write"], &reviewer),
        "scope_not_granted",
    );
    refused_with(
        issuer.harar_with(&["exchange", "--secret-env", "CHILD_SESSION", "--name", "x", "--aud", AUD], &reviewer),
        "audience_not_granted",
    );
    let tree = issuer.ok(&["session", "tree", &sid]);
    let sids: Vec<_> = tree.as_array().unwrap().iter().map(|s| s["sid"].as_str().unwrap()).collect();
    assert_eq!(sids, [sid.as_str(), child_sid.as_str()]);

    let refreshed = issuer.ok_with(&["session", "refresh", "--secret-env", "AVA_SESSION"], &ava);
    assert_eq!(refreshed["session"]["sid"], sid.as_str());

    let revoked = issuer.ok(&["session", "revoke", &sid]);
    assert_eq!(revoked.as_array().unwrap().len(), 2, "the revocation reports the whole tree");
    refused_with(
        issuer.harar_with(&["exchange", "--secret-env", "CHILD_SESSION", "--name", "y", "--aud", GILD], &reviewer),
        "session_not_live",
    );
    refused_with(issuer.harar_with(&["session", "refresh", "--secret-env", "AVA_SESSION"], &ava), "session_not_live");
    refused_with(
        issuer.harar(&["token", "--aud", AUD, "--scope", "deploy:staging", "--act", "agent:ava", "--session", &sid]),
        "session_not_live",
    );
}

#[test]
fn a_forged_or_foreign_session_token_is_refused() {
    let issuer = Issuer::start();
    grant_me(&issuer);
    let (_, ava_token) = start_ava(&issuer);
    // An access token for a service is not a session token, even with a sid.
    let child = issuer.ok_with(
        &["exchange", "--secret-env", "T", "--name", "c", "--aud", GILD, "--scope", "repo:read"],
        &[("T", ava_token.as_str())],
    );
    let access = child["token"].as_str().unwrap();
    refused_with(
        issuer.harar_with(&["exchange", "--secret-env", "T", "--name", "d", "--aud", GILD], &[("T", access)]),
        "invalid_session_token",
    );
    // Another issuer's session token.
    let other = Issuer::start();
    grant_me(&other);
    let (_, foreign) = start_ava(&other);
    refused_with(
        issuer.harar_with(&["exchange", "--secret-env", "T", "--name", "d", "--aud", GILD], &[("T", foreign.as_str())]),
        "invalid_session_token",
    );
}
