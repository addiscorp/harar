use super::*;
use harar_client::oidc::TokenAsk;

const ORG: &str = "gg.addis";

fn name(text: &str) -> Name {
    text.parse().unwrap()
}

fn peer(user: &str) -> PeerCred {
    PeerCred { uid: 4242, pid: 1, username: Some(user.into()) }
}

/// A new primary on bugsy, owned by sami as the OS user `sami`, keeping its
/// keys in a state file under `dir`.
async fn primary(dir: &Path) -> (Primary, age::x25519::Identity) {
    let identity = age::x25519::Identity::generate();
    let primary = with_identity(dir, &identity).await;
    let org: Org = ORG.parse().unwrap();
    let (policy, users) = first_policy(&org, &primary.zone, &primary.broker, &name("gg.addis.human.sami"), "sami", now_epoch_seconds()).unwrap();
    let mut keys = HashMap::new();
    store_policy(&mut keys, &policy, &users);
    primary.save(&keys).await.unwrap();
    *primary.keys.lock().await = keys;
    (primary, identity)
}

/// The same primary, restarted: everything comes back from the state file.
async fn with_identity(dir: &Path, identity: &age::x25519::Identity) -> Primary {
    let path = dir.join("keys.age");
    let keys = load_keys(&path, identity).unwrap();
    Primary {
        org: ORG.parse().unwrap(),
        zone: name("gg.addis.zone.bugsy"),
        broker: name("gg.addis.broker.bugsy"),
        keys: Mutex::new(keys),
        storage: Storage::File { path, recipient: identity.to_public() },
        issuer: oidc::Issuer::new("https://account.addis.gg", oidc::generate_es256_key(), harar_client::generate_signing_key()),
        audit_log: dir.join("audit.log"),
    }
}

async fn ask(primary: &Primary, user: &str, request: PrimaryRequest) -> PrimaryResponse {
    primary.handle(&peer(user), request).await
}

fn change(change: PolicyChange) -> PrimaryRequest {
    PrimaryRequest::PolicyChange { change }
}

fn refused(response: &PrimaryResponse) -> &str {
    assert!(!response.ok, "{response:?}");
    response.error.as_deref().unwrap()
}

/// The site service on bugsy may read and write prod/site/* and get deploy tokens.
async fn add_site(primary: &Primary) {
    let role = Role {
        name: name("gg.addis.role.site"),
        allows: vec![
            Permission { verb: Verb::Read, resource: "prod/site/*".into(), scopes: vec![] },
            Permission { verb: Verb::Write, resource: "prod/site/*".into(), scopes: vec![] },
            Permission { verb: Verb::Token, resource: "https://api.simien.dev".into(), scopes: vec!["deploy:site".into()] },
        ],
    };
    for step in [
        PolicyChange::SetRole { role },
        PolicyChange::Bind {
            binding: Binding { actor: "gg.addis.service.site".parse().unwrap(), zone: ZoneMatch::Name("gg.addis.zone.bugsy".parse().unwrap()), role: name("gg.addis.role.site") },
        },
        PolicyChange::MapUser { user: "site".into(), actor: name("gg.addis.service.site") },
    ] {
        assert!(ask(primary, "sami", change(step)).await.ok);
    }
}

#[tokio::test]
async fn the_owner_can_do_everything_on_a_new_primary() {
    let dir = tempfile::tempdir().unwrap();
    let (primary, _) = primary(dir.path()).await;
    assert!(ask(&primary, "sami", PrimaryRequest::Put { key: "prod/site/DATABASE_URL".into(), value: "postgres://x".into() }).await.ok);
    let got = ask(&primary, "sami", PrimaryRequest::Get { key: "prod/site/DATABASE_URL".into() }).await;
    assert_eq!(got.value.as_deref(), Some("postgres://x"));
    assert_eq!(ask(&primary, "sami", PrimaryRequest::List).await.keys.unwrap(), ["prod/site/DATABASE_URL"]);
    let shown = ask(&primary, "sami", PrimaryRequest::PolicyShow).await.policy.unwrap();
    assert_eq!(shown.users.get("sami"), Some(&name("gg.addis.human.sami")));
    assert_eq!(shown.zone, name("gg.addis.zone.bugsy"));
}

#[tokio::test]
async fn tokens_name_the_actor_its_org_zone_and_broker() {
    let dir = tempfile::tempdir().unwrap();
    let (primary, _) = primary(dir.path()).await;
    add_site(&primary).await;
    let ask_token = |scopes: Vec<&str>| PrimaryRequest::Token(TokenAsk {
        audience: "https://api.simien.dev".into(),
        scopes: scopes.into_iter().map(String::from).collect(),
        ttl_seconds: None,
        act: None,
        alg: None,
    });
    let response = ask(&primary, "site", ask_token(vec!["deploy:site"])).await;
    let token = response.token.expect("a token");
    let claims = oidc::verify_identity(&primary.issuer.jwks(), &token, "https://account.addis.gg", "https://api.simien.dev", now_epoch_seconds()).unwrap();
    assert_eq!(claims.sub, "gg.addis.service.site");
    assert_eq!(claims.extra["org"], "gg.addis");
    assert_eq!(claims.extra["zone"], "gg.addis.zone.bugsy");
    assert_eq!(claims.extra["via"], "gg.addis.broker.bugsy");
    assert_eq!(claims.exp - claims.iat, DEFAULT_TOKEN_SECONDS);
    assert_eq!(refused(&ask(&primary, "site", ask_token(vec!["deploy:site", "admin"])).await), "no_binding");
    let mut acting = TokenAsk { audience: "https://api.simien.dev".into(), scopes: vec![], ttl_seconds: None, act: Some(oidc::Actor { sub: "x".into(), sid: None, act: None }), alg: None };
    acting.scopes = vec!["deploy:site".into()];
    assert_eq!(refused(&ask(&primary, "site", PrimaryRequest::Token(acting)).await), "act_not_supported");
}

#[tokio::test]
async fn a_service_gets_its_own_secrets_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let (primary, _) = primary(dir.path()).await;
    add_site(&primary).await;
    for (key, value) in [("prod/site/DATABASE_URL", "postgres://site"), ("prod/billing/STRIPE_KEY", "sk-live")] {
        assert!(ask(&primary, "sami", PrimaryRequest::Put { key: key.into(), value: value.into() }).await.ok);
    }
    assert_eq!(ask(&primary, "site", PrimaryRequest::Get { key: "prod/site/DATABASE_URL".into() }).await.value.as_deref(), Some("postgres://site"));
    assert_eq!(refused(&ask(&primary, "site", PrimaryRequest::Get { key: "prod/billing/STRIPE_KEY".into() }).await), "no_binding");
    assert_eq!(refused(&ask(&primary, "site", PrimaryRequest::Get { key: "prod/site/../billing/STRIPE_KEY".into() }).await), "bad_path");
    assert_eq!(ask(&primary, "site", PrimaryRequest::List).await.keys.unwrap(), ["prod/site/DATABASE_URL"], "it only sees what it may read");
    assert_eq!(refused(&ask(&primary, "site", PrimaryRequest::Put { key: "prod/billing/X".into(), value: "x".into() }).await), "no_binding");
    assert_eq!(refused(&ask(&primary, "site", PrimaryRequest::PolicyShow).await), "no_binding", "it can't see the policy");
    assert_eq!(refused(&ask(&primary, "site", change(PolicyChange::UnmapUser { user: "sami".into() })).await), "no_binding", "nor change it");
}

#[tokio::test]
async fn os_users_the_policy_doesnt_map_get_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (primary, _) = primary(dir.path()).await;
    assert_eq!(refused(&ask(&primary, "mallory", PrimaryRequest::List).await), "unknown_caller");
    let nameless = PeerCred { uid: 99999, pid: 1, username: None };
    assert_eq!(refused(&primary.handle(&nameless, PrimaryRequest::Health).await), "unknown_caller");
}

#[tokio::test]
async fn the_primarys_own_entries_are_never_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let (primary, _) = primary(dir.path()).await;
    for key in [POLICY_KEY, USERS_KEY, "harar:anything"] {
        assert_eq!(refused(&ask(&primary, "sami", PrimaryRequest::Get { key: key.into() }).await), "reserved_key", "{key}");
        assert_eq!(refused(&ask(&primary, "sami", PrimaryRequest::Put { key: key.into(), value: "{}".into() }).await), "reserved_key", "{key}");
        assert_eq!(refused(&ask(&primary, "sami", PrimaryRequest::Delete { key: key.into() }).await), "reserved_key", "{key}");
    }
    assert!(ask(&primary, "sami", PrimaryRequest::List).await.keys.unwrap().is_empty(), "nor listed");
}

#[tokio::test]
async fn no_change_leaves_nobody_able_to_change_policy() {
    let dir = tempfile::tempdir().unwrap();
    let (primary, _) = primary(dir.path()).await;
    let owner_binding = Binding { actor: "gg.addis.human.sami".parse().unwrap(), zone: ZoneMatch::Name("gg.addis.zone.bugsy".parse().unwrap()), role: name("gg.addis.role.owner") };
    for lockout in [
        PolicyChange::UnmapUser { user: "sami".into() },
        PolicyChange::RemoveRole { name: name("gg.addis.role.owner") },
        PolicyChange::Unbind { binding: owner_binding.clone() },
        PolicyChange::RevokeZone { name: name("gg.addis.zone.bugsy") },
    ] {
        assert_eq!(refused(&ask(&primary, "sami", change(lockout.clone())).await), "would_lock_out", "{lockout:?}");
    }
    // With a second owner mapped, the first can step back.
    assert!(ask(&primary, "sami", change(PolicyChange::MapUser { user: "sami2".into(), actor: name("gg.addis.human.sami") })).await.ok);
    assert!(ask(&primary, "sami", change(PolicyChange::UnmapUser { user: "sami".into() })).await.ok);
    assert_eq!(refused(&ask(&primary, "sami", PrimaryRequest::List).await), "unknown_caller");
}

#[tokio::test]
async fn an_actor_who_may_only_narrow_cannot_widen() {
    let dir = tempfile::tempdir().unwrap();
    let (primary, _) = primary(dir.path()).await;
    add_site(&primary).await;
    let pruner = Role { name: name("gg.addis.role.pruner"), allows: vec![Permission { verb: Verb::Approve, resource: "policy.narrow".into(), scopes: vec![] }] };
    let bugsy = || ZoneMatch::Name("gg.addis.zone.bugsy".parse().unwrap());
    for setup in [
        PolicyChange::SetRole { role: pruner },
        PolicyChange::Bind { binding: Binding { actor: "gg.addis.agent.ava".parse().unwrap(), zone: bugsy(), role: name("gg.addis.role.pruner") } },
        PolicyChange::MapUser { user: "ava".into(), actor: name("gg.addis.agent.ava") },
    ] {
        assert!(ask(&primary, "sami", change(setup.clone())).await.ok, "{setup:?}");
    }
    let site = Binding { actor: "gg.addis.service.site".parse().unwrap(), zone: bugsy(), role: name("gg.addis.role.site") };
    let wider = Binding { actor: "gg.addis.agent.ava".parse().unwrap(), zone: bugsy(), role: name("gg.addis.role.owner") };
    assert_eq!(refused(&ask(&primary, "ava", change(PolicyChange::Bind { binding: wider })).await), "no_binding");
    assert!(ask(&primary, "ava", change(PolicyChange::Unbind { binding: site })).await.ok, "taking access away is allowed");
}

#[tokio::test]
async fn bad_changes_are_refused_and_good_ones_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (primary, identity) = primary(dir.path()).await;
    for bad in [
        PolicyChange::MapUser { user: "x".into(), actor: name("com.acme.service.x") },
        PolicyChange::MapUser { user: "x".into(), actor: name("gg.addis.user.u-1") },
        PolicyChange::MapUser { user: "".into(), actor: name("gg.addis.service.x") },
        PolicyChange::SetRole { role: Role { name: name("gg.addis.profile.x"), allows: vec![] } },
        PolicyChange::Bind { binding: Binding { actor: "gg.addis.service.x".parse().unwrap(), zone: ZoneMatch::Name("gg.addis.zone.bugsy".parse().unwrap()), role: name("gg.addis.profile.x") } },
        PolicyChange::RemoveRole { name: name("gg.addis.role.nothing") },
    ] {
        assert!(!ask(&primary, "sami", change(bad.clone())).await.ok, "{bad:?}");
    }
    add_site(&primary).await;
    assert!(ask(&primary, "sami", PrimaryRequest::Put { key: "prod/site/KEY".into(), value: "v".into() }).await.ok);
    drop(primary);

    let restarted = with_identity(dir.path(), &identity).await;
    assert_eq!(ask(&restarted, "site", PrimaryRequest::Get { key: "prod/site/KEY".into() }).await.value.as_deref(), Some("v"));
    let raw = fs::read(dir.path().join("keys.age")).unwrap();
    assert!(!raw.windows(21).any(|w| w == b"gg.addis.service.site"), "the policy is encrypted with everything else");
}

#[tokio::test]
async fn a_dry_run_says_what_would_happen() {
    let dir = tempfile::tempdir().unwrap();
    let (primary, _) = primary(dir.path()).await;
    add_site(&primary).await;
    let decide = |actor: Option<&str>, path: &str| PrimaryRequest::Decide { actor: actor.map(name), action: Action::Read { path: path.into() } };
    assert_eq!(ask(&primary, "sami", decide(Some("gg.addis.service.site"), "prod/site/X")).await.decision.as_deref(), Some("allow by gg.addis.role.site"));
    assert_eq!(ask(&primary, "sami", decide(Some("gg.addis.service.site"), "prod/other/X")).await.decision.as_deref(), Some("no_binding"));
    assert_eq!(refused(&ask(&primary, "site", decide(None, "prod/site/X")).await), "no_binding", "only those who may see the policy");
}

#[tokio::test]
async fn every_request_is_audited_with_who_asked() {
    let dir = tempfile::tempdir().unwrap();
    let (primary, _) = primary(dir.path()).await;
    ask(&primary, "sami", PrimaryRequest::Put { key: "prod/a".into(), value: "secret-value-123".into() }).await;
    ask(&primary, "mallory", PrimaryRequest::Get { key: "prod/a".into() }).await;
    let log = fs::read_to_string(dir.path().join("audit.log")).unwrap();
    let lines: Vec<serde_json::Value> = log.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(lines[0]["actor"], "gg.addis.human.sami");
    assert_eq!(lines[0]["subject"], "prod/a");
    assert_eq!(lines[1]["result"], "unknown_caller");
    assert!(!log.contains("secret-value-123"), "never the value");
}
