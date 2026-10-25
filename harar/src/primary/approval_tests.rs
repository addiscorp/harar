//! Approvals at the primary: once there are approver devices, a widening
//! waits for a person to approve it with one, and an OS account alone never
//! makes an approver.
use super::*;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use harar_client::approvals::{Decision, Proof};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::rand_core::OsRng;

const ORG: &str = "gg.addis";

fn name(text: &str) -> Name {
    text.parse().unwrap()
}

fn peer(user: &str) -> PeerCred {
    PeerCred { uid: 4242, pid: 1, username: Some(user.into()) }
}

async fn primary(dir: &Path) -> Primary {
    let identity = age::x25519::Identity::generate();
    let primary = Primary {
        org: ORG.parse().unwrap(),
        zone: name("gg.addis.zone.bugsy"),
        broker: name("gg.addis.broker.bugsy"),
        keys: Mutex::new(HashMap::new()),
        storage: Storage::File { path: dir.join("keys.age"), recipient: identity.to_public() },
        issuer: oidc::Issuer::new("https://account.addis.gg", oidc::generate_es256_key(), harar_client::generate_signing_key()),
        audit_log: dir.join("audit.log"),
        user_exists: |user| !user.starts_with("ghost"),
        unknown_lines: Default::default(),
    };
    let org: Org = ORG.parse().unwrap();
    let (policy, users) = first_policy(&org, &primary.zone, &primary.broker, &name("gg.addis.human.sami"), "sami", now_epoch_seconds()).unwrap();
    let mut keys = HashMap::new();
    store_policy(&mut keys, &policy, &users);
    primary.save(&keys).await.unwrap();
    *primary.keys.lock().await = keys;
    primary
}

async fn ask(primary: &Primary, user: &str, request: PrimaryRequest) -> PrimaryResponse {
    primary.handle(&peer(user), request).await
}

async fn change(primary: &Primary, user: &str, change: PolicyChange) -> PrimaryResponse {
    ask(primary, user, PrimaryRequest::PolicyChange { change }).await
}

fn refused(response: &PrimaryResponse) -> &str {
    assert!(!response.ok, "{response:?}");
    response.error.as_deref().unwrap()
}

fn key() -> SigningKey {
    SigningKey::random(&mut OsRng)
}

/// What `harar device add` sends: a Mac key that asks first; the primary fills in the rest.
fn mac(key: &SigningKey) -> ApproverDevice {
    let point = key.verifying_key().to_encoded_point(false);
    ApproverDevice {
        id: String::new(),
        human: name("x.x.human.nobody"),
        kind: DeviceKind::Mac,
        public_key: harar_client::Jwk {
            kty: "EC".into(),
            kid: String::new(),
            crv: "P-256".into(),
            alg: "ES256".into(),
            key_use: "sig".into(),
            x: URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            y: Some(URL_SAFE_NO_PAD.encode(point.y().unwrap())),
        },
        credential_id: None,
        enrolled_at: 0,
        user_verification: true,
        backup_eligible: false,
        sign_count: 0,
        reserved_after: 0,
        revoked: false,
    }
}

/// Dates every device a minute back, as if enrolled before what follows (a
/// device never approves a request older than itself).
async fn backdate(primary: &Primary) {
    let mut keys = primary.keys.lock().await;
    let mut devices = load_devices(&keys);
    for device in &mut devices {
        device.enrolled_at = device.enrolled_at.saturating_sub(60);
    }
    store_devices(&mut keys, &devices);
}

/// The bootstrap device: the first one there is, enrolled at once.
async fn first_device(primary: &Primary, user: &str, key: &SigningKey) -> String {
    let added = ask(primary, user, PrimaryRequest::AddDevice { device: mac(key) }).await;
    assert!(added.ok && added.pending.is_none(), "{added:?}");
    backdate(primary).await;
    added.value.unwrap()
}

fn signed(pending: &Pending, device: &str, key: &SigningKey, decision: Decision) -> PrimaryRequest {
    let signature: Signature = key.sign(&pending.request.challenge(decision, device));
    PrimaryRequest::Submit {
        approval: Approval {
            request_id: pending.request.id.clone(),
            device_id: device.into(),
            decision,
            proof: Proof::Signature { signature: URL_SAFE_NO_PAD.encode(signature.to_der()) },
        },
    }
}

/// A device enrolled after the first: it waits, an approver's device approves it.
async fn another_device(primary: &Primary, user: &str, key: &SigningKey, approver: (&str, &SigningKey)) -> String {
    let pending = ask(primary, user, PrimaryRequest::AddDevice { device: mac(key) }).await.pending.expect("it waits");
    let id = match &pending.waiting {
        Waiting::Device { device } => device.id.clone(),
        other => panic!("{other:?}"),
    };
    let decided = ask(primary, user, signed(&pending, approver.0, approver.1, Decision::Approve)).await;
    assert_eq!(decided.decision.as_deref(), Some("approved"), "{decided:?}");
    backdate(primary).await;
    id
}

fn site_role() -> PolicyChange {
    PolicyChange::SetRole {
        role: Role { name: name("gg.addis.role.site"), allows: vec![Permission { verb: Verb::Read, resource: "prod/site/*".into(), scopes: vec![] }] },
    }
}

async fn has_site_role(primary: &Primary) -> bool {
    let shown = ask(primary, "sami", PrimaryRequest::PolicyShow).await.policy.unwrap();
    shown.policy.roles.iter().any(|role| role.name == name("gg.addis.role.site"))
}

async fn waiting(primary: &Primary) -> Vec<Pending> {
    ask(primary, "sami", PrimaryRequest::Approvals).await.approvals.unwrap()
}

async fn devices(primary: &Primary) -> Vec<ApproverDevice> {
    ask(primary, "sami", PrimaryRequest::Approvals).await.devices.unwrap()
}

/// The owner's role, which may approve everything.
async fn owner_role(primary: &Primary) -> Name {
    let shown = ask(primary, "sami", PrimaryRequest::PolicyShow).await.policy.unwrap();
    shown.policy.bindings.iter().find(|binding| binding.actor == "gg.addis.human.sami".parse().unwrap()).unwrap().role.clone()
}

/// Bob, a second person, mapped as the OS user `bob`; an approver too when `approver`.
async fn add_bob(primary: &Primary, approver: bool) {
    assert!(change(primary, "sami", PolicyChange::MapUser { user: "bob".into(), actor: name("gg.addis.human.bob") }).await.ok);
    if approver {
        let role = owner_role(primary).await;
        let binding = Binding { actor: "gg.addis.human.bob".parse().unwrap(), zone: ZoneMatch::Name("gg.addis.zone.bugsy".parse().unwrap()), role };
        assert!(change(primary, "sami", PolicyChange::Bind { binding }).await.ok);
    }
}

#[tokio::test]
async fn without_devices_a_widening_applies_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    let response = change(&primary, "sami", site_role()).await;
    assert!(response.ok && response.pending.is_none(), "{response:?}");
    assert!(has_site_role(&primary).await);
}

#[tokio::test]
async fn with_a_device_a_widening_waits_and_applies_only_once_approved() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    let key = key();
    let device = first_device(&primary, "sami", &key).await;
    let pending = change(&primary, "sami", site_role()).await.pending.expect("it waits");
    assert!(!has_site_role(&primary).await, "nothing changed yet");
    // Asked by the machine's broker for the OS user's actor, so their own device can approve it.
    assert_eq!(pending.request.actor, name("gg.addis.broker.bugsy"));
    assert_eq!(pending.request.act_for, Some(name("gg.addis.human.sami")));
    // Exactly what it would do is signed with it.
    assert_eq!(pending.request.detail.as_deref(), Some(waiting_detail(&pending.waiting).as_str()));
    assert!(pending.description.contains("gg.addis.role.site"), "{}", pending.description);
    assert_eq!(waiting(&primary).await.len(), 1);
    let decided = ask(&primary, "sami", signed(&pending, &device, &key, Decision::Approve)).await;
    assert_eq!(decided.decision.as_deref(), Some("approved"), "{decided:?}");
    assert!(has_site_role(&primary).await);
    // Acted on once.
    assert!(waiting(&primary).await.is_empty());
    assert_eq!(refused(&ask(&primary, "sami", signed(&pending, &device, &key, Decision::Approve)).await), "no_such_request");
    // The audit line names the device and the person who decided.
    let audit = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    assert!(audit.contains(&format!("{} by {device} (gg.addis.human.sami): approved", pending.request.id)), "{audit}");
}

#[tokio::test]
async fn a_denial_drops_the_request_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    let key = key();
    let device = first_device(&primary, "sami", &key).await;
    let pending = change(&primary, "sami", site_role()).await.pending.unwrap();
    let decided = ask(&primary, "sami", signed(&pending, &device, &key, Decision::Deny)).await;
    assert_eq!(decided.decision.as_deref(), Some("denied"));
    assert!(!has_site_role(&primary).await);
    assert!(waiting(&primary).await.is_empty());
}

#[tokio::test]
async fn a_bad_signature_is_refused_and_kept_nowhere() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    let key = key();
    let device = first_device(&primary, "sami", &key).await;
    let pending = change(&primary, "sami", site_role()).await.pending.unwrap();
    assert_eq!(refused(&ask(&primary, "sami", signed(&pending, &device, &self::key(), Decision::Approve)).await), "bad_proof");
    // A signature for the other decision doesn't count for this one.
    let mut flipped = signed(&pending, &device, &key, Decision::Deny);
    if let PrimaryRequest::Submit { approval } = &mut flipped {
        approval.decision = Decision::Approve;
    }
    assert_eq!(refused(&ask(&primary, "sami", flipped).await), "bad_proof");
    assert!(!has_site_role(&primary).await);
    assert_eq!(waiting(&primary).await.len(), 1);
    let stored = load_waiting(&*primary.keys.lock().await, now_epoch_seconds());
    assert!(stored[0].approvals.is_empty(), "nothing unverified is kept");
}

#[tokio::test]
async fn only_a_human_the_policy_lets_approve_counts() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    // Bob may approve device enrollments, and nothing else.
    add_bob(&primary, false).await;
    let devices_only = Role {
        name: name("gg.addis.role.devices"),
        allows: vec![Permission { verb: Verb::Approve, resource: "approvals.device".into(), scopes: vec![] }],
    };
    assert!(change(&primary, "sami", PolicyChange::SetRole { role: devices_only }).await.ok);
    let binding = Binding { actor: "gg.addis.human.bob".parse().unwrap(), zone: ZoneMatch::Name("gg.addis.zone.bugsy".parse().unwrap()), role: name("gg.addis.role.devices") };
    assert!(change(&primary, "sami", PolicyChange::Bind { binding }).await.ok);
    let sami = key();
    let sami_device = first_device(&primary, "sami", &sami).await;
    let bob = key();
    // Bob's device is enrolled only because sami approved it.
    let bob_device = another_device(&primary, "bob", &bob, (&sami_device, &sami)).await;
    let pending = change(&primary, "sami", site_role()).await.pending.unwrap();
    assert_eq!(refused(&ask(&primary, "bob", signed(&pending, &bob_device, &bob, Decision::Approve)).await), "not_an_approver");
    assert!(!has_site_role(&primary).await);
}

#[tokio::test]
async fn someone_who_approves_nothing_gets_no_device() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    add_bob(&primary, false).await;
    first_device(&primary, "sami", &key()).await;
    // So nobody without approval rights can fill the waiting list either.
    assert_eq!(refused(&ask(&primary, "bob", PrimaryRequest::AddDevice { device: mac(&key()) }).await), "not_an_approver");
    assert!(waiting(&primary).await.is_empty());
}

#[tokio::test]
async fn the_first_device_must_be_an_approvers() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    add_bob(&primary, false).await;
    // Someone who can't approve can't start approvals (and freeze every change).
    assert_eq!(refused(&ask(&primary, "bob", PrimaryRequest::AddDevice { device: mac(&key()) }).await), "not_an_approver");
    assert!(devices(&primary).await.is_empty());
    assert!(change(&primary, "sami", site_role()).await.pending.is_none(), "still no devices: it applies");
}

#[tokio::test]
async fn an_os_account_alone_never_makes_an_approver() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    add_bob(&primary, true).await;
    let sami = key();
    let sami_device = first_device(&primary, "sami", &sami).await;
    let bob = key();
    another_device(&primary, "bob", &bob, (&sami_device, &sami)).await;
    // Someone with sami's OS account: with bob's device left, removing sami's goes through...
    assert!(ask(&primary, "sami", PrimaryRequest::RemoveDevice { id: sami_device }).await.ok);
    // ...but their own key, as sami's "first" device, only waits; it approves nothing.
    let intruder = key();
    let added = ask(&primary, "sami", PrimaryRequest::AddDevice { device: mac(&intruder) }).await;
    let pending = added.pending.expect("it waits for an approver's device");
    assert!(pending.description.contains(&harar_client::approvals::device_fingerprint(&mac(&intruder))), "{}", pending.description);
    let id = match &pending.waiting {
        Waiting::Device { device } => device.id.clone(),
        other => panic!("{other:?}"),
    };
    assert_eq!(refused(&ask(&primary, "sami", signed(&pending, &id, &intruder, Decision::Approve)).await), "unknown_device");
    let widening = change(&primary, "sami", site_role()).await.pending.unwrap();
    assert_eq!(refused(&ask(&primary, "sami", signed(&widening, &id, &intruder, Decision::Approve)).await), "unknown_device");
    assert!(!has_site_role(&primary).await);
}

#[tokio::test]
async fn handing_out_approver_rights_is_its_own_class() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    let sami = key();
    let sami_device = first_device(&primary, "sami", &sami).await;
    assert!(change(&primary, "sami", PolicyChange::MapUser { user: "bob".into(), actor: name("gg.addis.human.bob") }).await.pending.is_some());
    let role = owner_role(&primary).await;
    let binding = Binding { actor: "gg.addis.human.bob".parse().unwrap(), zone: ZoneMatch::Name("gg.addis.zone.bugsy".parse().unwrap()), role };
    let pending = change(&primary, "sami", PolicyChange::Bind { binding }).await.pending.unwrap();
    assert_eq!(pending.request.class, "approvals.grant");
    assert!(pending.request.grants_approval);
    assert_eq!(ask(&primary, "sami", signed(&pending, &sami_device, &sami, Decision::Approve)).await.decision.as_deref(), Some("approved"));
}

#[tokio::test]
async fn taking_away_still_applies_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    assert!(change(&primary, "sami", site_role()).await.ok);
    first_device(&primary, "sami", &key()).await;
    let response = change(&primary, "sami", PolicyChange::RemoveRole { name: name("gg.addis.role.site") }).await;
    assert!(response.ok && response.pending.is_none(), "{response:?}");
    assert!(!has_site_role(&primary).await);
}

#[tokio::test]
async fn another_device_waits_for_one_already_there() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    let first = key();
    let first_id = first_device(&primary, "sami", &first).await;
    let second = key();
    let pending = ask(&primary, "sami", PrimaryRequest::AddDevice { device: mac(&second) }).await.pending.expect("it waits");
    assert!(pending.request.grants_approval);
    assert_eq!(devices(&primary).await.len(), 1);
    // The same key waits once, and a key enrolled once is never enrolled again.
    assert_eq!(refused(&ask(&primary, "sami", PrimaryRequest::AddDevice { device: mac(&second) }).await), "already_waiting");
    assert_eq!(refused(&ask(&primary, "sami", PrimaryRequest::AddDevice { device: mac(&first) }).await), "key_enrolled");
    assert_eq!(ask(&primary, "sami", signed(&pending, &first_id, &first, Decision::Approve)).await.decision.as_deref(), Some("approved"));
    let all = devices(&primary).await;
    assert_eq!(all.len(), 2);
    assert!(all.iter().all(|device| device.human == name("gg.addis.human.sami")), "always the caller's own");
}

#[tokio::test]
async fn the_last_device_that_can_approve_a_widening_stays() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    let first = key();
    let first_id = first_device(&primary, "sami", &first).await;
    assert_eq!(refused(&ask(&primary, "sami", PrimaryRequest::RemoveDevice { id: first_id.clone() }).await), "would_lock_out");
    another_device(&primary, "sami", &key(), (&first_id, &first)).await;
    // With two, one can go; the other then can't.
    assert!(ask(&primary, "sami", PrimaryRequest::RemoveDevice { id: first_id }).await.ok);
    let left = devices(&primary).await.into_iter().find(|device| !device.revoked).unwrap();
    assert_eq!(refused(&ask(&primary, "sami", PrimaryRequest::RemoveDevice { id: left.id }).await), "would_lock_out");
    // And a widening still waits: losing a device never means the OS user alone may widen again.
    assert!(change(&primary, "sami", site_role()).await.pending.is_some());
}

#[tokio::test]
async fn no_one_asker_fills_the_waiting_list() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    first_device(&primary, "sami", &key()).await;
    for n in 0..MAX_WAITING_PER_ASKER {
        let role = Role { name: name(&format!("gg.addis.role.r{n}")), allows: vec![] };
        assert!(change(&primary, "sami", PolicyChange::SetRole { role }).await.pending.is_some());
    }
    assert_eq!(refused(&change(&primary, "sami", site_role()).await), "too_many_waiting");
}

#[tokio::test]
async fn a_lapsed_request_cant_be_approved() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    let key = key();
    let device = first_device(&primary, "sami", &key).await;
    let pending = change(&primary, "sami", site_role()).await.pending.unwrap();
    {
        let mut keys = primary.keys.lock().await;
        let mut all: Vec<Stored> = serde_json::from_str(&keys[WAITING_KEY]).unwrap();
        all[0].request.expires_at = now_epoch_seconds() - 1;
        store_waiting(&mut keys, &all);
    }
    assert_eq!(refused(&ask(&primary, "sami", signed(&pending, &device, &key, Decision::Approve)).await), "no_such_request");
    assert!(!has_site_role(&primary).await);
}

#[tokio::test]
async fn only_mac_keys_that_ask_first_are_enrolled() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    let key = key();
    let mut unverified = mac(&key);
    unverified.user_verification = false;
    assert_eq!(refused(&ask(&primary, "sami", PrimaryRequest::AddDevice { device: unverified }).await), "bad_device");
    let mut passkey = mac(&key);
    passkey.kind = DeviceKind::Passkey;
    assert_eq!(refused(&ask(&primary, "sami", PrimaryRequest::AddDevice { device: passkey }).await), "bad_device");
    let mut garbage = mac(&key);
    garbage.public_key.x = "AAAA".into();
    assert_eq!(refused(&ask(&primary, "sami", PrimaryRequest::AddDevice { device: garbage }).await), "bad_device");
}
