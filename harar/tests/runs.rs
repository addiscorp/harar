//! Scenario S3 end to end: a gild host registers an agent's deploy run; the
//! build inside the run's VM gets production secrets only after the env rule
//! passes and a person approves; then it gets a token simien can trust.

mod common;

use common::*;
use harar_client::oidc;

const SIMIEN: &str = "https://api.simien.dev";

fn set_up(issuer: &Issuer) {
    issuer.ok(&["workload", "add", "svc:ci@test", "--user", &me(), "--runs-for", "addiscorp/*"]);
    for (key, value) in [("prod/site/DATABASE_URL", "postgres://prod"), ("prod/site/API_KEY", "key-prod"), ("dev/site/OTHER", "dev-only")] {
        issuer.ok_with(&["put", key, "--secret-env", "V"], &[("V", value)]);
    }
    issuer.ok(&[
        "env", "rule", "production", "--repo", "addiscorp/site", "--ref", "refs/heads/main", "--workflow", "deploy.yml",
        "--secrets", "prod/site/*", "--aud", SIMIEN, "--approve-when-agent",
    ]);
}

fn register(issuer: &Issuer, git_ref: &str, actor: &str) -> (String, String) {
    let out = issuer.ok(&[
        "runs", "register", "--repo", "addiscorp/site", "--sha", "4e1a9c0", "--ref", git_ref, "--workflow", "deploy.yml",
        "--env", "production", "--actor", actor, "--for", "user:sami",
    ]);
    (out["run"]["id"].as_str().unwrap().to_string(), out["run_token"].as_str().unwrap().to_string())
}

/// What the build step in the VM runs. It reports what it saw without
/// printing values, which harar would conceal anyway.
const BUILD: &str = r#"test "$DATABASE_URL" = postgres://prod && echo db-ok; test "$KEY" = key-prod && echo ref-ok; test -z "$OTHER" && echo no-dev; test -z "$HARAR_RUN_TOKEN" && echo no-token; echo "printed=$API_KEY""#;

#[test]
fn an_agents_deploy_gets_production_only_after_a_person_says_yes() {
    let issuer = Issuer::start();
    set_up(&issuer);
    let (id, run_token) = register(&issuer, "refs/heads/main", "agent:ava");
    let vm = [("HARAR_RUN_TOKEN", run_token.as_str()), ("KEY", "harar://prod/site/API_KEY")];
    let build = ["run", "--env", "production", "--", "sh", "-c", BUILD];

    refused_with(issuer.harar_with(&build, &vm), "approval_pending");
    let pending = issuer.ok(&["approvals", "list"]);
    assert_eq!(pending[0]["id"], id.as_str());
    assert_eq!(pending[0]["facts"]["actor"], "agent:ava");
    issuer.ok(&["approvals", "approve", &id]);

    let out = issuer.harar_with(&build, &vm);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout, "db-ok\nref-ok\nno-dev\nno-token\nprinted=<concealed by harar>\n");

    // A reference outside the environment fails before the build starts.
    let outside = [("HARAR_RUN_TOKEN", run_token.as_str()), ("X", "harar://dev/site/OTHER")];
    refused_with(issuer.harar_with(&["run", "--env", "production", "--", "true"], &outside), "doesn't include");
    refused_with(issuer.harar_with(&["run", "--env", "staging", "--", "true"], &vm), "wrong_env");

    // Trusted publishing: a token carrying the run's facts, for simien only.
    let token = issuer.ok_with(&["runs", "token", "--aud", SIMIEN, "--secret-env", "HARAR_RUN_TOKEN"], &vm);
    let claims = oidc::verify_identity(&issuer.jwks(), token["token"].as_str().unwrap(), &issuer.url, SIMIEN, now()).unwrap();
    assert_eq!(claims.sub, "run:addiscorp/site:deploy.yml:production");
    for (claim, value) in [("repo", "addiscorp/site"), ("sha", "4e1a9c0"), ("ref", "refs/heads/main"), ("env", "production"), ("actor", "agent:ava")] {
        assert_eq!(claims.extra[claim], value, "{claim}");
    }
    assert_eq!(claims.extra["run"], id.as_str());
    assert_eq!(claims.act.unwrap().chain(), ["agent:ava", "user:sami"]);
    refused_with(
        issuer.harar_with(&["runs", "token", "--aud", "https://gild.gg", "--secret-env", "HARAR_RUN_TOKEN"], &vm),
        "audience_not_granted",
    );

    issuer.ok(&["runs", "finish", &id]);
    refused_with(issuer.harar_with(&build, &vm), "run_not_live");
}

#[test]
fn runs_the_rule_does_not_cover_get_nothing() {
    let issuer = Issuer::start();
    set_up(&issuer);
    let (_, feature) = register(&issuer, "refs/heads/feature", "user:sami");
    refused_with(
        issuer.harar_with(&["run", "--env", "production", "--", "true"], &[("HARAR_RUN_TOKEN", feature.as_str())]),
        "env_rule_refuses",
    );

    // A person's run on main needs no approval.
    let (_, main) = register(&issuer, "refs/heads/main", "user:sami");
    let out = issuer.harar_with(&["run", "--env", "production", "--", "sh", "-c", BUILD], &[("HARAR_RUN_TOKEN", main.as_str()), ("KEY", "harar://prod/site/API_KEY")]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    // A session token is not a run token.
    issuer.ok(&["workload", "add", "svc:ci@test", "--user", &me(), "--sessions-for", "agent:*", "--runs-for", "addiscorp/*"]);
    issuer.ok(&["policy", "allow", "svc:ci@test", "--aud", AUD, "--scope", "deploy:*"]);
    let started = issuer.ok(&["session", "start", "agent:ava", "--grant", &format!("{AUD}=deploy:staging")]);
    let session_token = started["session_token"].as_str().unwrap();
    refused_with(
        issuer.harar_with(&["run", "--env", "production", "--", "true"], &[("HARAR_RUN_TOKEN", session_token)]),
        "invalid_run_token",
    );
    refused_with(issuer.harar_with(&["run", "--env", "production", "--", "true"], &[]), "HARAR_RUN_TOKEN");
}
