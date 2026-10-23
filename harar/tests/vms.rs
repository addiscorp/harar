//! Scenario S2 A end to end, over real vsock: the host registers a VM's CID,
//! `harar vm serve` answers on a vsock port, and the "VM" (this machine, over
//! vsock loopback, CID 1) gets tokens and build secrets as that VM, without
//! holding any token of its own.
//!
//! Needs the `vsock_loopback` kernel module. Where it can't be loaded, set
//! `HARAR_TEST_NO_VSOCK=1`; the test then checks vsock really is unreachable.
#![cfg(target_os = "linux")]

mod common;

use common::*;
use harar_client::oidc;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const LOOPBACK_CID: &str = "1";

struct VmService {
    child: Child,
    port: String,
}

impl Drop for VmService {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn serve(issuer: &Issuer) -> VmService {
    let port = (20_000 + std::process::id() % 20_000).to_string();
    let child = Command::new(env!("CARGO_BIN_EXE_harar"))
        .args(["vm", "serve", "--port", &port])
        .env("HARAR_SOCKET", &issuer.socket)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn harar vm serve");
    // Give it a moment to bind; vsock has no cheap "is it listening" probe.
    std::thread::sleep(Duration::from_millis(300));
    VmService { child, port }
}

fn in_vm(issuer: &Issuer, service: &VmService, args: &[&str]) -> std::process::Output {
    let mut all: Vec<&str> = args.to_vec();
    all.extend(["--host-cid", LOOPBACK_CID, "--vsock-port", &service.port]);
    // The VM holds nothing: no socket to the issuer, no run token.
    Command::new(env!("CARGO_BIN_EXE_harar"))
        .args(&all)
        .env_remove("HARAR_RUN_TOKEN")
        .env("HARAR_SOCKET", "/nonexistent/harar.sock")
        .output()
        .unwrap_or_else(|err| panic!("run harar in the VM ({:?}): {err}", issuer.url))
}

fn vsock_missing(issuer: &Issuer, service: &VmService) -> bool {
    if std::env::var_os("HARAR_TEST_NO_VSOCK").is_none() {
        return false;
    }
    let out = in_vm(issuer, service, &["vm", "token", "--aud", AUD]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("reach the host over vsock"),
        "HARAR_TEST_NO_VSOCK is set but vsock loopback works: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    true
}

#[test]
fn a_vm_gets_tokens_and_build_secrets_as_itself_over_vsock() {
    let issuer = Issuer::start();
    issuer.ok(&["workload", "add", "svc:ci@test", "--user", &me(), "--sessions-for", "agent:*", "--runs-for", "addiscorp/*"]);
    issuer.ok(&["policy", "allow", "svc:ci@test", "--aud", AUD, "--scope", "deploy:*"]);
    issuer.ok(&["policy", "allow", "svc:ci@test", "--aud", GILD, "--scope", "repo:*"]);
    let (sid, _) = start_ava(&issuer);
    issuer.ok(&["vm", "register", "--cid", LOOPBACK_CID, "--name", "r88", "--session", &sid]);
    let service = serve(&issuer);
    if vsock_missing(&issuer, &service) {
        return;
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    let out = loop {
        let out = in_vm(&issuer, &service, &["vm", "token", "--aud", GILD, "--scope", "repo:read"]);
        if out.status.success() || Instant::now() > deadline {
            break out;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let reply: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let claims = oidc::verify_identity(&issuer.jwks(), reply["token"].as_str().unwrap(), &issuer.url, GILD, now()).unwrap();
    assert_eq!(claims.sub, "vm:r88", "the kernel said which VM asked");
    assert_eq!(claims.act.unwrap().chain(), ["agent:ava", "user:sami"]);
    refused_with(in_vm(&issuer, &service, &["vm", "token", "--aud", AUD, "--scope", "deploy:production"]), "scope_not_in_session");

    // The same CID, reused for a CI run: build secrets with no run token.
    issuer.ok_with(&["put", "prod/site/DATABASE_URL", "--secret-env", "V"], &[("V", "postgres://prod")]);
    issuer.ok(&[
        "env", "rule", "production", "--repo", "addiscorp/site", "--ref", "refs/heads/main", "--workflow", "deploy.yml",
        "--secrets", "prod/site/*",
    ]);
    let run = issuer.ok(&[
        "runs", "register", "--repo", "addiscorp/site", "--sha", "4e1a9c0", "--ref", "refs/heads/main", "--workflow",
        "deploy.yml", "--env", "production", "--actor", "user:sami",
    ]);
    let run_id = run["run"]["id"].as_str().unwrap();
    issuer.ok(&["vm", "register", "--cid", LOOPBACK_CID, "--name", "build-1", "--run", run_id]);
    let build = Command::new(env!("CARGO_BIN_EXE_harar"))
        .args(["run", "--env", "production", "--from-host", "--host-cid", LOOPBACK_CID, "--vsock-port", &service.port])
        .args(["--", "sh", "-c", r#"test "$DATABASE_URL" = postgres://prod && echo db-ok; test -z "$HARAR_RUN_TOKEN" && echo no-token"#])
        .env_remove("HARAR_RUN_TOKEN")
        .env("HARAR_SOCKET", "/nonexistent/harar.sock")
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&build.stdout), "db-ok\nno-token\n", "{}", String::from_utf8_lossy(&build.stderr));

    issuer.ok(&["vm", "forget", "--cid", LOOPBACK_CID]);
    refused_with(in_vm(&issuer, &service, &["vm", "token", "--aud", GILD]), "unknown_vm");
}
