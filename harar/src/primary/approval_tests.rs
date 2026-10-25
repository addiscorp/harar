//! Approvals at the primary: once a person has an approver device, a
//! widening waits for them to approve it with that device.
use super::*;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use harar_client::approvals::{Decision, Proof};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};

const ORG: &str = "gg.addis";

fn name(text: &str) -> Name {
    text.parse().unwrap()
}

fn peer(user: &str) -> PeerCred {
    PeerCred {
        uid: 4242,
        pid: 1,
        username: Some(user.into()),
    }
}

async fn primary(dir: &Path) -> Primary {
    let identity = age::x25519::Identity::generate();
    let path = dir.join("keys.age");
    let primary = Primary {
        org: ORG.parse().unwrap(),
        zone: name("gg.addis.zone.bugsy"),
        broker: name("gg.addis.broker.bugsy"),
        keys: Mutex::new(HashMap::new()),
        storage: Storage::File {
            path,
            recipient: identity.to_public(),
        },
        issuer: oidc::Issuer::new(
            "https://account.addis.gg",
            oidc::generate_es256_key(),
            harar_client::generate_signing_key(),
        ),
        audit_log: dir.join("audit.log"),
        user_exists: |user| !user.starts_with("ghost"),
        unknown_lines: Default::default(),
    };
    let org: Org = ORG.parse().unwrap();
    let (policy, users) = first_policy(
        &org,
        &primary.zone,
        &primary.broker,
        &name("gg.addis.human.sami"),
        "sami",
        now_epoch_seconds(),
    )
    .unwrap();
    let mut keys = HashMap::new();
    store_policy(&mut keys, &policy, &users);
    primary.save(&keys).await.unwrap();
    *primary.keys.lock().await = keys;
    primary
}

async fn ask(primary: &Primary, user: &str, request: PrimaryRequest) -> PrimaryResponse {
    primary.handle(&peer(user), request).await
}

fn refused(response: &PrimaryResponse) -> &str {
    assert!(!response.ok, "{response:?}");
    response.error.as_deref().unwrap()
}

/// What `harar device add` sends: a Mac key, user-verified; the primary fills in the rest.
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

/// Enrolls a device for `user` and dates it a minute back, as if it had been
/// enrolled before anything that follows (a device never approves a request
/// older than itself).
async fn enroll(primary: &Primary, user: &str, key: &SigningKey) -> String {
    let added = ask(
        primary,
        user,
        PrimaryRequest::AddDevice { device: mac(key) },
    )
    .await;
    assert!(added.ok, "{added:?}");
    let id = added.value.expect("enrolled at once");
    backdate(primary).await;
    id
}

async fn backdate(primary: &Primary) {
    let mut keys = primary.keys.lock().await;
    let mut devices = load_devices(&keys);
    for device in &mut devices {
        device.enrolled_at = device.enrolled_at.saturating_sub(60);
    }
    store_devices(&mut keys, &devices);
}

fn signed(pending: &Pending, device: &str, key: &SigningKey, decision: Decision) -> PrimaryRequest {
    let signature: Signature = key.sign(&pending.request.challenge(decision, device));
    PrimaryRequest::Submit {
        approval: Approval {
            request_id: pending.request.id.clone(),
            device_id: device.into(),
            decision,
            proof: Proof::Signature {
                signature: URL_SAFE_NO_PAD.encode(signature.to_der()),
            },
        },
    }
}

fn site_role() -> PolicyChange {
    PolicyChange::SetRole {
        role: Role {
            name: name("gg.addis.role.site"),
            allows: vec![Permission {
                verb: Verb::Read,
                resource: "prod/site/*".into(),
                scopes: vec![],
            }],
        },
    }
}

async fn has_site_role(primary: &Primary) -> bool {
    let shown = ask(primary, "sami", PrimaryRequest::PolicyShow)
        .await
        .policy
        .unwrap();
    shown
        .policy
        .roles
        .iter()
        .any(|role| role.name == name("gg.addis.role.site"))
}

async fn waiting(primary: &Primary) -> Vec<Pending> {
    ask(primary, "sami", PrimaryRequest::Approvals)
        .await
        .approvals
        .unwrap()
}

#[tokio::test]
async fn without_devices_a_widening_applies_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    let response = ask(
        &primary,
        "sami",
        PrimaryRequest::PolicyChange {
            change: site_role(),
        },
    )
    .await;
    assert!(response.ok && response.pending.is_none(), "{response:?}");
    assert!(has_site_role(&primary).await);
}

#[tokio::test]
async fn with_a_device_a_widening_waits_and_applies_only_once_approved() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let device = enroll(&primary, "sami", &key).await;
    let response = ask(
        &primary,
        "sami",
        PrimaryRequest::PolicyChange {
            change: site_role(),
        },
    )
    .await;
    let pending = response.pending.expect("it waits");
    assert!(!has_site_role(&primary).await, "nothing changed yet");
    // Asked by the machine's broker for the OS user's actor, so their own device can approve it.
    assert_eq!(pending.request.actor, name("gg.addis.broker.bugsy"));
    assert_eq!(pending.request.act_for, Some(name("gg.addis.human.sami")));
    assert!(
        pending.description.contains("gg.addis.role.site"),
        "{}",
        pending.description
    );
    assert_eq!(waiting(&primary).await.len(), 1);
    let decided = ask(
        &primary,
        "sami",
        signed(&pending, &device, &key, Decision::Approve),
    )
    .await;
    assert_eq!(decided.decision.as_deref(), Some("approved"), "{decided:?}");
    assert!(has_site_role(&primary).await);
    // Acted on once.
    assert!(waiting(&primary).await.is_empty());
    assert_eq!(
        refused(
            &ask(
                &primary,
                "sami",
                signed(&pending, &device, &key, Decision::Approve)
            )
            .await
        ),
        "no_such_request"
    );
}

#[tokio::test]
async fn a_denial_drops_the_request_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let device = enroll(&primary, "sami", &key).await;
    let pending = ask(
        &primary,
        "sami",
        PrimaryRequest::PolicyChange {
            change: site_role(),
        },
    )
    .await
    .pending
    .unwrap();
    let decided = ask(
        &primary,
        "sami",
        signed(&pending, &device, &key, Decision::Deny),
    )
    .await;
    assert_eq!(decided.decision.as_deref(), Some("denied"));
    assert!(!has_site_role(&primary).await);
    assert!(waiting(&primary).await.is_empty());
}

#[tokio::test]
async fn a_bad_signature_is_refused_and_kept_nowhere() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let device = enroll(&primary, "sami", &key).await;
    let pending = ask(
        &primary,
        "sami",
        PrimaryRequest::PolicyChange {
            change: site_role(),
        },
    )
    .await
    .pending
    .unwrap();
    let other = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    assert_eq!(
        refused(
            &ask(
                &primary,
                "sami",
                signed(&pending, &device, &other, Decision::Approve)
            )
            .await
        ),
        "bad_proof"
    );
    // A signature for the other decision doesn't count for this one.
    let mut flipped = signed(&pending, &device, &key, Decision::Deny);
    if let PrimaryRequest::Submit { approval } = &mut flipped {
        approval.decision = Decision::Approve;
    }
    assert_eq!(refused(&ask(&primary, "sami", flipped).await), "bad_proof");
    assert!(!has_site_role(&primary).await);
    let still = waiting(&primary).await;
    assert_eq!(still.len(), 1);
    let stored = load_waiting(&*primary.keys.lock().await, now_epoch_seconds());
    assert!(stored[0].approvals.is_empty(), "nothing unverified is kept");
}

#[tokio::test]
async fn only_a_human_the_policy_lets_approve_counts() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    // Ana is a person here, with no right to approve anything.
    assert!(
        ask(
            &primary,
            "sami",
            PrimaryRequest::PolicyChange {
                change: PolicyChange::MapUser {
                    user: "ana".into(),
                    actor: name("gg.addis.human.ana")
                }
            }
        )
        .await
        .ok
    );
    let ana = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let ana_device = enroll(&primary, "ana", &ana).await;
    let sami = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    enroll(&primary, "sami", &sami).await;
    let pending = ask(
        &primary,
        "sami",
        PrimaryRequest::PolicyChange {
            change: site_role(),
        },
    )
    .await
    .pending
    .unwrap();
    assert_eq!(
        refused(
            &ask(
                &primary,
                "ana",
                signed(&pending, &ana_device, &ana, Decision::Approve)
            )
            .await
        ),
        "not_an_approver"
    );
    assert!(!has_site_role(&primary).await);
}

#[tokio::test]
async fn taking_away_still_applies_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    assert!(
        ask(
            &primary,
            "sami",
            PrimaryRequest::PolicyChange {
                change: site_role()
            }
        )
        .await
        .ok
    );
    let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    enroll(&primary, "sami", &key).await;
    let response = ask(
        &primary,
        "sami",
        PrimaryRequest::PolicyChange {
            change: PolicyChange::RemoveRole {
                name: name("gg.addis.role.site"),
            },
        },
    )
    .await;
    assert!(response.ok && response.pending.is_none(), "{response:?}");
    assert!(!has_site_role(&primary).await);
}

#[tokio::test]
async fn another_device_waits_for_one_the_person_already_has() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    let first = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let first_id = enroll(&primary, "sami", &first).await;
    let second = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let added = ask(
        &primary,
        "sami",
        PrimaryRequest::AddDevice {
            device: mac(&second),
        },
    )
    .await;
    let pending = added.pending.expect("the second device waits");
    assert!(pending.request.grants_approval);
    assert_eq!(
        ask(&primary, "sami", PrimaryRequest::Approvals)
            .await
            .devices
            .unwrap()
            .len(),
        1
    );
    let decided = ask(
        &primary,
        "sami",
        signed(&pending, &first_id, &first, Decision::Approve),
    )
    .await;
    assert_eq!(decided.decision.as_deref(), Some("approved"), "{decided:?}");
    let devices = ask(&primary, "sami", PrimaryRequest::Approvals)
        .await
        .devices
        .unwrap();
    assert_eq!(devices.len(), 2);
    assert!(
        devices
            .iter()
            .all(|device| device.human == name("gg.addis.human.sami")),
        "always the caller's own"
    );
}

#[tokio::test]
async fn the_last_device_that_can_approve_a_widening_stays() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    let first = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let first_id = enroll(&primary, "sami", &first).await;
    assert_eq!(
        refused(
            &ask(
                &primary,
                "sami",
                PrimaryRequest::RemoveDevice {
                    id: first_id.clone()
                }
            )
            .await
        ),
        "would_lock_out"
    );
    let second = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let pending = ask(
        &primary,
        "sami",
        PrimaryRequest::AddDevice {
            device: mac(&second),
        },
    )
    .await
    .pending
    .unwrap();
    assert_eq!(
        ask(
            &primary,
            "sami",
            signed(&pending, &first_id, &first, Decision::Approve)
        )
        .await
        .decision
        .as_deref(),
        Some("approved")
    );
    // With two, one can go; the other then can't.
    assert!(
        ask(
            &primary,
            "sami",
            PrimaryRequest::RemoveDevice { id: first_id }
        )
        .await
        .ok
    );
    let left = ask(&primary, "sami", PrimaryRequest::Approvals)
        .await
        .devices
        .unwrap()
        .into_iter()
        .find(|d| !d.revoked)
        .unwrap();
    assert_eq!(
        refused(
            &ask(
                &primary,
                "sami",
                PrimaryRequest::RemoveDevice { id: left.id }
            )
            .await
        ),
        "would_lock_out"
    );
    // And a widening still waits: losing a device never means the OS user alone may widen again.
    assert!(
        ask(
            &primary,
            "sami",
            PrimaryRequest::PolicyChange {
                change: site_role()
            }
        )
        .await
        .pending
        .is_some()
    );
}

#[tokio::test]
async fn a_lapsed_request_cant_be_approved() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let device = enroll(&primary, "sami", &key).await;
    let pending = ask(
        &primary,
        "sami",
        PrimaryRequest::PolicyChange {
            change: site_role(),
        },
    )
    .await
    .pending
    .unwrap();
    {
        let mut keys = primary.keys.lock().await;
        let mut all: Vec<Stored> = serde_json::from_str(&keys[WAITING_KEY]).unwrap();
        all[0].request.expires_at = now_epoch_seconds() - 1;
        store_waiting(&mut keys, &all);
    }
    assert_eq!(
        refused(
            &ask(
                &primary,
                "sami",
                signed(&pending, &device, &key, Decision::Approve)
            )
            .await
        ),
        "no_such_request"
    );
    assert!(!has_site_role(&primary).await);
}

#[tokio::test]
async fn only_mac_keys_that_ask_first_are_enrolled() {
    let dir = tempfile::tempdir().unwrap();
    let primary = primary(dir.path()).await;
    let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let mut unverified = mac(&key);
    unverified.user_verification = false;
    assert_eq!(
        refused(
            &ask(
                &primary,
                "sami",
                PrimaryRequest::AddDevice { device: unverified }
            )
            .await
        ),
        "bad_device"
    );
    let mut passkey = mac(&key);
    passkey.kind = DeviceKind::Passkey;
    assert_eq!(
        refused(
            &ask(
                &primary,
                "sami",
                PrimaryRequest::AddDevice { device: passkey }
            )
            .await
        ),
        "bad_device"
    );
    let mut garbage = mac(&key);
    garbage.public_key.x = "AAAA".into();
    assert_eq!(
        refused(
            &ask(
                &primary,
                "sami",
                PrimaryRequest::AddDevice { device: garbage }
            )
            .await
        ),
        "bad_device"
    );
}
