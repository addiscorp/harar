//! Scenario S6 end to end: a new host enrolls with its own key over the
//! issuer's public listener, a person approves it by code, and the host then
//! gets tokens for its workloads by signing assertions.

mod common;

use common::*;
use harar_client::oidc;

fn enroll(issuer: &Issuer, dir: &std::path::Path, name: &str) -> (std::process::Output, std::path::PathBuf) {
    let key_file = dir.join(format!("{name}.key"));
    let out = issuer.harar(&[
        "host", "enroll", name, "--issuer", &issuer.url, "--key-file", key_file.to_str().unwrap(), "--software",
    ]);
    (out, key_file)
}

fn host_token(issuer: &Issuer, key_file: &std::path::Path, sub: &str, scope: &str) -> std::process::Output {
    issuer.harar(&[
        "host", "token", "--issuer", &issuer.url, "--key-file", key_file.to_str().unwrap(), "--as", sub, "--aud", AUD,
        "--scope", scope,
    ])
}

#[test]
fn a_new_host_joins_by_code_and_gets_tokens_for_its_workloads() {
    let issuer = Issuer::start();
    let dir = tempfile::tempdir().unwrap();
    let (out, key_file) = enroll(&issuer, dir.path(), "bugsy");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let enrolled: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let code = enrolled["code"].as_str().unwrap();
    assert_eq!(enrolled["tier"], "software");
    assert!(String::from_utf8_lossy(&out.stderr).contains(&format!("harar host approve bugsy --code {code}")));

    issuer.ok(&["policy", "allow", "svc:gild@bugsy", "--aud", AUD, "--scope", "deploy:*"]);
    refused_with(host_token(&issuer, &key_file, "svc:gild@bugsy", "deploy:staging"), "unknown_host");

    let listed = issuer.ok(&["host", "list"]);
    assert_eq!(listed["pending"]["bugsy"]["code"], code, "both screens show the same code");
    refused_with(issuer.harar(&["host", "approve", "bugsy", "--code", "0000-0000"]), "code_mismatch");
    issuer.ok(&["host", "approve", "bugsy", "--code", code]);

    let out = host_token(&issuer, &key_file, "svc:gild@bugsy", "deploy:staging");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let reply: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let claims = oidc::verify_identity(&issuer.jwks(), reply["token"].as_str().unwrap(), &issuer.url, AUD, now()).unwrap();
    assert_eq!(claims.sub, "svc:gild@bugsy");
    assert_eq!(claims.scope, "deploy:staging");
    assert_eq!(claims.extra["host"], "bugsy");
    assert_eq!(claims.extra["host_tier"], "software");

    refused_with(host_token(&issuer, &key_file, "svc:gild@demon", "deploy:staging"), "not_this_hosts_workload");
    refused_with(host_token(&issuer, &key_file, "svc:gild@bugsy", "admin:all"), "scope_not_granted");
    issuer.ok(&["policy", "allow", "svc:db@bugsy", "--aud", AUD, "--scope", "deploy:*", "--hardware-only"]);
    refused_with(host_token(&issuer, &key_file, "svc:db@bugsy", "deploy:staging"), "hardware_required");

    issuer.ok(&["host", "remove", "bugsy"]);
    refused_with(host_token(&issuer, &key_file, "svc:gild@bugsy", "deploy:staging"), "unknown_host");
}

#[test]
fn enrollment_names_are_first_come_and_keys_are_never_overwritten() {
    let issuer = Issuer::start();
    let dir = tempfile::tempdir().unwrap();
    let (first, key_file) = enroll(&issuer, dir.path(), "bugsy");
    assert!(first.status.success());
    let other = tempfile::tempdir().unwrap();
    let (second, _) = enroll(&issuer, other.path(), "bugsy");
    refused_with(second, "name_pending");
    assert!(!other.path().join("bugsy.key").exists(), "a refused enrollment leaves no key behind");

    // Enrolling again on the same host would orphan its key.
    let again = issuer.harar(&[
        "host", "enroll", "bugsy", "--issuer", &issuer.url, "--key-file", key_file.to_str().unwrap(), "--software",
    ]);
    refused_with(again, "already enrolled");
    issuer.ok(&["host", "reject", "bugsy"]);
    assert!(issuer.ok(&["host", "list"])["pending"].as_object().unwrap().is_empty());
}

#[test]
fn the_public_listener_rejects_junk_posts() {
    let issuer = Issuer::start();
    let post = |path: &str, body: &str| {
        use std::io::{Read, Write};
        let mut stream = std::net::TcpStream::connect(&issuer.address).unwrap();
        // The server may answer and hang up before reading a body it refuses.
        let _ = write!(stream, "POST {path} HTTP/1.1\r\nHost: x\r\ncontent-length: {}\r\n\r\n{body}", body.len());
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        response
    };
    assert!(post("/v1/token", r#"{"assertion":"a.b.c"}"#).contains("403"));
    assert!(post("/v1/token", "not json").contains("400"));
    assert!(post("/v1/hosts/enroll", r#"{"name":"x"}"#).contains("400"));
    assert!(post("/v1/secret/anything", "{}").contains("404"));
    let huge = format!(r#"{{"assertion":"{}"}}"#, "a".repeat(64 * 1024));
    assert!(post("/v1/token", &huge).contains("400"), "bodies over 16 KB are refused");
}
