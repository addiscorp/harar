//! Approvals (architecture, section 6): a human approves from a device that
//! signs only after Face ID, Touch ID or a PIN, over the exact request, so a
//! signature can't be replayed onto anything else. A coordinator agent may
//! approve anything its role names, except the reserved classes, which only a
//! person can approve, and never anything that raises its own reach or its
//! lineage's.
//!
//! What a device shows is `ApprovalRequest::describe`, computed from the same
//! fields the signature covers; nothing the requester writes freely is shown.
//! The signed bytes are a fixed binary encoding (`challenge`), pinned by a
//! known-answer test, so the Simien app and passkey page can rebuild them.

use crate::model::{Action, Kind, Name, NamePattern, Org};
use crate::Jwk;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const CHALLENGE_CONTEXT: &[u8] = b"harar.approval.v4";

/// The longest a request may wait for approval.
pub const MAX_REQUEST_SECONDS: u64 = 24 * 3600;
const CLOCK_SKEW_SECONDS: u64 = 60;

/// What only a person may approve, on their own device: the actions that
/// could take over or blind the whole system. Anything under them
/// (`device.enroll`, `keys.rotate`) counts as them.
/// - `device`: adding or removing approver devices;
/// - `approvals`: changing who may approve what, the coordinator's powers too;
/// - `audit`: turning off or removing the audit trail;
/// - `trust`: trusting another org or issuer;
/// - `keys`: rotating the master key or the signing keys.
///
/// - `recovery`, `setup`: recovery codes and setup links, which stand in for a device;
/// - `hosts`: enrolling a machine, which joins the trust root;
/// - `issuer`, `store`: the primary's own identity and storage;
/// - `policy.rollback`: restoring an earlier policy, which can widen anything.
///
/// Also reserved, whatever its class says: granting approver rights
/// (`Action::Approve`, or any change with `grants_approval`), and any class
/// that isn't well formed. No synced passkey approves a reserved class.
pub const RESERVED_CLASSES: [&str; 11] =
    ["device", "approvals", "audit", "trust", "keys", "recovery", "setup", "hosts", "issuer", "store", "policy.rollback"];

/// `segment(.segment)*`, each segment `[a-z0-9-]`, at most 128 characters.
pub fn valid_class(class: &str) -> bool {
    class.len() <= 128
        && class.split('.').all(|segment| !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
}

/// Whether a class is a person's alone. A malformed class counts as one, so
/// a typo never lands with a coordinator.
pub fn is_reserved(class: &str) -> bool {
    !valid_class(class) || RESERVED_CLASSES.iter().any(|root| class == *root || class.strip_prefix(root).is_some_and(|rest| rest.starts_with('.')))
}

/// Whose reach a request widens. Required: a request that doesn't say is
/// never read as widening nobody.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "names", rename_all = "lowercase")]
pub enum Reach {
    /// It gives more to nobody (a deploy, a read, a narrowing).
    None,
    /// It gives more to exactly these actors.
    Actors(Vec<Name>),
    /// It gives more to anything these patterns match, now or later (a role
    /// or binding edit).
    Patterns(Vec<NamePattern>),
    /// The primary can't bound it. No coordinator approves these.
    Unbounded,
}

impl Reach {
    /// Whether this widens `name`'s reach.
    pub fn touches(&self, name: &Name) -> bool {
        match self {
            Reach::None => false,
            Reach::Actors(names) => names.contains(name),
            Reach::Patterns(patterns) => patterns.iter().any(|pattern| pattern.matches(name)),
            Reach::Unbounded => true,
        }
    }
}

/// Text a device shows must be one plain token: printable ASCII with no
/// spaces, so it can't be padded off screen, imitate the words around it, or
/// hide control and direction-changing characters.
fn plain(text: &str) -> bool {
    !text.is_empty() && text.len() <= 256 && text.bytes().all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
}

const MAX_SCOPES: usize = 16;
const MAX_CHAIN: usize = 8;
/// The longest description a device is asked to show.
const MAX_DESCRIPTION: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceKind {
    /// A Secure Enclave key on a Mac, made for approving, that asks first.
    /// Never the key `harar agent` unlocks with.
    Mac,
    /// A WebAuthn passkey, on any phone or laptop.
    Passkey,
    /// The Simien app's Vault (iOS Secure Enclave, Android StrongBox).
    Phone,
}

/// A key in hardware a human carries, enrolled to approve as them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverDevice {
    pub id: String,
    pub human: Name,
    pub kind: DeviceKind,
    /// P-256.
    pub public_key: Jwk,
    /// For passkeys, the WebAuthn credential id, so the approval page asks
    /// for exactly this credential (`allowCredentials`, one per ceremony):
    /// the device id is in what's signed, so the page must know it first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    pub enrolled_at: u64,
    /// Enrollment proved (by platform attestation, or the passkey's UV flag)
    /// that this key signs only after biometrics or a PIN. Devices without
    /// it never approve.
    pub user_verification: bool,
    /// A synced passkey (WebAuthn backup-eligible): it lives in a cloud
    /// account, not only in hardware the human carries. Never enough for the
    /// highest classes.
    #[serde(default)]
    pub backup_eligible: bool,
    /// The passkey's signature counter last seen. Each use must raise it, so
    /// a cloned authenticator is caught (synced passkeys always send 0).
    #[serde(default)]
    pub sign_count: u32,
    #[serde(default)]
    pub revoked: bool,
}

impl ApproverDevice {
    /// The key itself, so one key enrolled twice counts once.
    fn key_bytes(&self) -> String {
        format!("{}|{}", self.public_key.x, self.public_key.y.as_deref().unwrap_or_default())
    }
}

/// The primary deciding: its issuer URL, which every request must name, the
/// site its passkeys belong to, and how many of a person's devices a reserved
/// class needs. All from its own config, never from a request or a device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Primary {
    pub issuer: String,
    pub rp_id: String,
    /// Devices a reserved class needs: 1 to start; 2 once every approver has
    /// two devices enrolled.
    pub reserved_devices: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Approve,
    Deny,
}

/// Something waiting for a person. The primary fills every field from what
/// it authenticated; none comes from the requester's own say-so.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Random, at least 128 bits, made by the primary.
    pub id: String,
    /// Which primary is asking (its issuer URL), so an approval for one never
    /// counts on another, staging and production included.
    pub primary: String,
    pub org: Org,
    pub class: String,
    /// Who is asking.
    pub actor: Name,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act_for: Option<Name>,
    /// Everything that started the actor, nearest first: the session or
    /// orchestrator that launched it, and so on up.
    #[serde(default)]
    pub chain: Vec<Name>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<Name>,
    pub action: Action,
    /// Whose reach this widens. The primary computes it from policy.
    pub affects: Reach,
    /// Whether this gives anyone approver rights: `Action::Approve`, or a role
    /// or binding change that includes `approve`. Always a person's to decide.
    pub grants_approval: bool,
    pub created_at: u64,
    pub expires_at: u64,
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn optional(out: &mut Vec<u8>, name: &Option<Name>) {
    match name {
        None => out.push(0),
        Some(name) => {
            out.push(1);
            field(out, name.to_string().as_bytes());
        }
    }
}

fn list(out: &mut Vec<u8>, items: &[String]) {
    out.extend_from_slice(&(items.len() as u64).to_be_bytes());
    for item in items {
        field(out, item.as_bytes());
    }
}

/// One byte for the kind of action, then its fields.
fn encode_action(out: &mut Vec<u8>, action: &Action) {
    match action {
        Action::Read { path } => {
            out.push(1);
            field(out, path.as_bytes());
        }
        Action::Write { path } => {
            out.push(2);
            field(out, path.as_bytes());
        }
        Action::Token { audience, scopes } => {
            out.push(3);
            field(out, audience.as_bytes());
            list(out, scopes);
        }
        Action::Launch { profile } => {
            out.push(4);
            field(out, profile.to_string().as_bytes());
        }
        Action::Approve { class } => {
            out.push(5);
            field(out, class.as_bytes());
        }
    }
}

impl ApprovalRequest {
    /// The bytes a device signs (and its signer hashes once more, as
    /// `ecdsaSignatureMessageX962SHA256` / `SHA256withECDSA` / WebAuthn do):
    /// SHA-256 over a fixed encoding of every field and the decision.
    ///
    /// `context || device_id || id || primary || org || class || actor || act_for? ||
    /// chain[] || zone? || action || reach || grants_approval || created_at ||
    /// expires_at || decision`, the reach as one tag byte (0 nobody, 1 actors,
    /// 2 patterns, 3 unbounded) then for 1 and 2 a list, grants_approval as 0 or 1,
    /// strings as u64 big-endian length then bytes, optionals as 0 or 1 then
    /// the string, lists as a u64 count then each string, the action as one
    /// tag byte (1 read, 2 write, 3 token, 4 launch, 5 approve) then its
    /// fields, times as u64 big-endian, decision as 1 approve, 0 deny.
    pub fn challenge(&self, decision: Decision, device_id: &str) -> [u8; 32] {
        let mut out = CHALLENGE_CONTEXT.to_vec();
        field(&mut out, device_id.as_bytes());
        for part in [self.id.as_str(), self.primary.as_str(), self.org.as_str(), self.class.as_str(), &self.actor.to_string()] {
            field(&mut out, part.as_bytes());
        }
        optional(&mut out, &self.act_for);
        list(&mut out, &self.chain.iter().map(Name::to_string).collect::<Vec<_>>());
        optional(&mut out, &self.zone);
        encode_action(&mut out, &self.action);
        match &self.affects {
            Reach::None => out.push(0),
            Reach::Actors(names) => {
                out.push(1);
                list(&mut out, &names.iter().map(Name::to_string).collect::<Vec<_>>());
            }
            Reach::Patterns(patterns) => {
                out.push(2);
                list(&mut out, &patterns.iter().map(NamePattern::to_string).collect::<Vec<_>>());
            }
            Reach::Unbounded => out.push(3),
        }
        out.push(u8::from(self.grants_approval));
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.push(match decision {
            Decision::Approve => 1,
            Decision::Deny => 0,
        });
        Sha256::digest(&out).into()
    }

    /// What a device shows, computed only from signed fields.
    pub fn describe(&self) -> String {
        let what = match &self.action {
            Action::Read { path } => format!("read the secret \"{path}\""),
            Action::Write { path } => format!("change the secret \"{path}\""),
            Action::Token { audience, scopes } => {
                let scopes: Vec<String> = scopes.iter().map(|scope| format!("\"{scope}\"")).collect();
                format!("get a token for \"{audience}\" with scopes [{}]", scopes.join(" "))
            }
            Action::Launch { profile } => format!("start a {profile} zone"),
            Action::Approve { class } => format!("approve \"{class}\" requests"),
        };
        let mut text = format!("[{} {} on {}] {} wants to {what}", self.class, self.org, self.primary, self.actor);
        if let Some(act_for) = &self.act_for {
            text.push_str(&format!("; for {act_for}"));
        }
        if let Some(zone) = &self.zone {
            text.push_str(&format!("; from {zone}"));
        }
        match &self.affects {
            Reach::None => {}
            Reach::Actors(names) => text.push_str(&format!("; gives more to {}", names.iter().map(Name::to_string).collect::<Vec<_>>().join(" "))),
            Reach::Patterns(patterns) => {
                text.push_str(&format!("; gives more to anything matching {}", patterns.iter().map(NamePattern::to_string).collect::<Vec<_>>().join(" ")))
            }
            Reach::Unbounded => text.push_str("; gives more to an unknown set"),
        }
        if self.grants_approval {
            text.push_str("; grants approver rights");
        }
        text
    }

    /// Whether only a person may approve this: a reserved class, or a grant
    /// of approver rights, whatever its class says.
    pub fn is_reserved(&self) -> bool {
        is_reserved(&self.class) || self.grants_approval || matches!(self.action, Action::Approve { .. })
    }

    /// The request itself is well formed, for this primary, and still open.
    fn check(&self, primary: &Primary, now: u64) -> Result<(), ApprovalError> {
        let id_ok = self.id.len() >= 26 && self.id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if !valid_class(&self.class) || !id_ok || self.primary != primary.issuer {
            return Err(ApprovalError::BadRequest);
        }
        if let Action::Approve { class } = &self.action {
            if !valid_class(class) {
                return Err(ApprovalError::BadRequest);
            }
        }
        if let Action::Read { path } | Action::Write { path } = &self.action {
            if !crate::model::valid_secret_path(path) {
                return Err(ApprovalError::BadRequest);
            }
        }
        if let Action::Token { scopes, .. } = &self.action {
            if scopes.len() > MAX_SCOPES {
                return Err(ApprovalError::BadRequest);
            }
        }
        if self.chain.len() > MAX_CHAIN
            || match &self.affects {
                Reach::Actors(names) => names.is_empty() || names.len() > MAX_CHAIN || !names.iter().all(|name| name.kind().is_actor() && name.org() == &self.org),
                Reach::Patterns(patterns) => patterns.is_empty() || patterns.len() > MAX_CHAIN || !patterns.iter().all(|pattern| pattern.kind().is_actor() && pattern.org() == &self.org),
                Reach::None | Reach::Unbounded => false,
            }
            || !self.actor.kind().is_actor()
            || self.zone.as_ref().is_some_and(|zone| zone.kind() != Kind::Zone)
            || self.act_for.as_ref().is_some_and(|who| !matches!(who.kind(), Kind::Human | Kind::User))
            || !self.chain.iter().all(|name| name.kind().is_actor())
        {
            return Err(ApprovalError::BadRequest);
        }
        if let Action::Launch { profile } = &self.action {
            if profile.kind() != Kind::Profile || profile.org() != &self.org {
                return Err(ApprovalError::BadRequest);
            }
        }
        let texts: Vec<&str> = match &self.action {
            Action::Read { path } | Action::Write { path } => vec![path],
            Action::Token { audience, scopes } => std::iter::once(audience.as_str()).chain(scopes.iter().map(String::as_str)).collect(),
            Action::Approve { class } => vec![class],
            Action::Launch { .. } => vec![],
        };
        if !texts.iter().all(|text| plain(text)) {
            return Err(ApprovalError::BadRequest);
        }
        let mut names = std::iter::once(&self.actor).chain(&self.act_for).chain(&self.chain).chain(&self.zone);
        if names.any(|name| name.org() != &self.org) {
            return Err(ApprovalError::BadRequest);
        }
        if self.created_at > now + CLOCK_SKEW_SECONDS || self.expires_at <= self.created_at || self.expires_at - self.created_at > MAX_REQUEST_SECONDS {
            return Err(ApprovalError::BadRequest);
        }
        if self.describe().len() > MAX_DESCRIPTION {
            return Err(ApprovalError::BadRequest);
        }
        if now >= self.expires_at {
            return Err(ApprovalError::Expired);
        }
        Ok(())
    }

    /// The classes whose rules this request must satisfy: its own, and for a
    /// grant of approver rights, the granted class too, so a grant is never
    /// judged by a looser rule than the rights it gives.
    fn governing_classes(&self) -> Vec<&str> {
        let mut classes = vec![self.class.as_str()];
        if let Action::Approve { class } = &self.action {
            classes.push(class);
        }
        classes
    }
}

/// How a device proved it signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Proof {
    /// Mac and phone: ECDSA P-256 (SHA-256) over the challenge, DER, base64url.
    Signature { signature: String },
    /// A passkey's WebAuthn assertion, each part base64url.
    WebAuthn { authenticator_data: String, client_data_json: String, signature: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub request_id: String,
    pub device_id: String,
    pub decision: Decision,
    pub proof: Proof,
}

/// Who may approve a class, and how many of their device keys it takes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRule {
    /// A class, or a class prefix followed by `.*` (`deploy.*`).
    pub class: String,
    /// Humans who may approve.
    pub approvers: NamePattern,
    /// How many of one approver's distinct device keys must agree (at least
    /// 1; reserved classes need at least the primary's `reserved_devices`).
    pub devices: u8,
}

impl ApprovalRule {
    /// How closely the rule fits `class`: None if not at all; an exact class
    /// beats any prefix, and a longer prefix beats a shorter one.
    fn fit(&self, class: &str) -> Option<usize> {
        match self.class.strip_suffix(".*") {
            Some(prefix) => class.strip_prefix(prefix).filter(|rest| rest.starts_with('.')).map(|_| prefix.len()),
            None => (self.class == class).then_some(usize::MAX),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Approved,
    Denied,
    Pending { have: usize, need: usize },
}

/// Where a request stands, which submissions didn't count and why, and the
/// passkey counters to store for the ones that did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decided {
    pub outcome: Outcome,
    pub rejected: Vec<(usize, ApprovalError)>,
    pub sign_counts: BTreeMap<String, u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalError {
    BadRequest,
    Expired,
    NoRule,
    AmbiguousRules,
    WrongRequest,
    UnknownDevice,
    DeviceRevoked,
    DeviceTooNew,
    DeviceUnverified,
    NotAnApprover,
    OwnRequest,
    SyncedPasskey,
    DuplicateKey,
    BadProof,
}

impl ApprovalError {
    pub fn as_str(self) -> &'static str {
        match self {
            ApprovalError::BadRequest => "bad_request",
            ApprovalError::Expired => "expired",
            ApprovalError::NoRule => "no_rule_for_class",
            ApprovalError::AmbiguousRules => "ambiguous_rules",
            ApprovalError::WrongRequest => "wrong_request",
            ApprovalError::UnknownDevice => "unknown_device",
            ApprovalError::DeviceRevoked => "device_revoked",
            ApprovalError::DeviceTooNew => "device_enrolled_after_request",
            ApprovalError::DeviceUnverified => "device_not_user_verified",
            ApprovalError::NotAnApprover => "not_an_approver",
            ApprovalError::OwnRequest => "own_request",
            ApprovalError::SyncedPasskey => "synced_passkey",
            ApprovalError::DuplicateKey => "key_enrolled_twice",
            ApprovalError::BadProof => "bad_proof",
        }
    }
}

fn decode(value: &str) -> Result<Vec<u8>, ApprovalError> {
    B64URL.decode(value).map_err(|_| ApprovalError::BadProof)
}

fn verifying_key(device: &ApproverDevice) -> Result<VerifyingKey, ApprovalError> {
    if device.public_key.kty != "EC" || device.public_key.crv != "P-256" {
        return Err(ApprovalError::BadProof);
    }
    crate::oidc::es256_verifying_key(&device.public_key).map_err(|_| ApprovalError::BadProof)
}

/// Checks a WebAuthn assertion (W3C WebAuthn, §7.2): a `webauthn.get` for
/// this challenge from the relying party's own origin, not from inside
/// another site's frame; authenticator data for that relying party with the
/// user present and verified; a signature counter that moved on; and a
/// signature over both. Returns the new counter.
fn verify_webauthn(
    key: &VerifyingKey,
    device: &ApproverDevice,
    rp: &Primary,
    challenge: &[u8; 32],
    reserved: bool,
    proof: (&[u8], &[u8], &[u8]),
) -> Result<u32, ApprovalError> {
    let (authenticator_data, client_data_json, signature) = proof;
    #[derive(Deserialize)]
    struct ClientData {
        #[serde(rename = "type")]
        kind: String,
        challenge: String,
        origin: String,
        #[serde(rename = "crossOrigin", default)]
        cross_origin: bool,
        #[serde(rename = "topOrigin", default)]
        top_origin: Option<String>,
    }
    let client: ClientData = serde_json::from_slice(client_data_json).map_err(|_| ApprovalError::BadProof)?;
    if client.kind != "webauthn.get"
        || client.challenge != B64URL.encode(challenge)
        || client.origin != format!("https://{}", rp.rp_id)
        || client.cross_origin
        || client.top_origin.is_some()
    {
        return Err(ApprovalError::BadProof);
    }
    // rpIdHash (32) | flags (1) | signCount (4) | …
    if authenticator_data.len() < 37 || authenticator_data[..32] != Sha256::digest(rp.rp_id.as_bytes())[..] {
        return Err(ApprovalError::BadProof);
    }
    let flags = authenticator_data[32];
    const USER_PRESENT: u8 = 0x01;
    const USER_VERIFIED: u8 = 0x04;
    const BACKUP_ELIGIBLE: u8 = 0x08;
    const BACKUP_STATE: u8 = 0x10;
    if flags & USER_PRESENT == 0 || flags & USER_VERIFIED == 0 {
        return Err(ApprovalError::BadProof);
    }
    let mut signed = authenticator_data.to_vec();
    signed.extend_from_slice(&Sha256::digest(client_data_json));
    let signature = Signature::from_der(signature).map_err(|_| ApprovalError::BadProof)?;
    key.verify(&signed, &signature).map_err(|_| ApprovalError::BadProof)?;
    if reserved && (device.backup_eligible || flags & (BACKUP_ELIGIBLE | BACKUP_STATE) != 0) {
        return Err(ApprovalError::SyncedPasskey);
    }
    let count = u32::from_be_bytes(authenticator_data[33..37].try_into().expect("four bytes"));
    if (count != 0 || device.sign_count != 0) && count <= device.sign_count {
        return Err(ApprovalError::BadProof);
    }
    Ok(count)
}

/// Checks one approval against its device and this request. Returns the
/// device, and the passkey counter to store if it was a passkey.
pub fn verify_approval<'a>(
    request: &ApprovalRequest,
    approval: &Approval,
    devices: &'a [ApproverDevice],
    rp: &Primary,
) -> Result<(&'a ApproverDevice, Option<u32>), ApprovalError> {
    if approval.request_id != request.id {
        return Err(ApprovalError::WrongRequest);
    }
    let device = devices.iter().find(|device| device.id == approval.device_id).ok_or(ApprovalError::UnknownDevice)?;
    if device.revoked {
        return Err(ApprovalError::DeviceRevoked);
    }
    if device.human.kind() != Kind::Human || device.human.org() != &request.org {
        return Err(ApprovalError::NotAnApprover);
    }
    if device.enrolled_at >= request.created_at {
        return Err(ApprovalError::DeviceTooNew);
    }
    if !device.user_verification {
        return Err(ApprovalError::DeviceUnverified);
    }
    let key = verifying_key(device)?;
    let challenge = request.challenge(approval.decision, &device.id);
    let count = match (&approval.proof, device.kind) {
        (Proof::Signature { signature }, DeviceKind::Mac | DeviceKind::Phone) => {
            let signature = Signature::from_der(&decode(signature)?).map_err(|_| ApprovalError::BadProof)?;
            key.verify(&challenge, &signature).map_err(|_| ApprovalError::BadProof)?;
            None
        }
        (Proof::WebAuthn { authenticator_data, client_data_json, signature }, DeviceKind::Passkey) => {
            let parts = (decode(authenticator_data)?, decode(client_data_json)?, decode(signature)?);
            Some(verify_webauthn(&key, device, rp, &challenge, request.is_reserved(), (&parts.0, &parts.1, &parts.2))?)
        }
        _ => return Err(ApprovalError::BadProof),
    };
    Ok((device, count))
}

/// The rule that governs `class`: the closest fit, whatever the list order.
pub fn rule_for<'a>(rules: &'a [ApprovalRule], class: &str) -> Result<&'a ApprovalRule, ApprovalError> {
    let mut fits: Vec<(usize, &ApprovalRule)> = rules.iter().filter_map(|rule| rule.fit(class).map(|fit| (fit, rule))).collect();
    fits.sort_by_key(|(fit, _)| std::cmp::Reverse(*fit));
    match fits.as_slice() {
        [] => Err(ApprovalError::NoRule),
        [(best, _), (next, _), ..] if best == next => Err(ApprovalError::AmbiguousRules),
        [(_, rule), ..] => Ok(rule),
    }
}

/// Where a request stands, given everything submitted for it. Submissions
/// that don't verify, or come from someone the rule doesn't name, are set
/// aside (`rejected`) and change nothing, so nobody can block a request by
/// sending junk. A valid deny from an allowed approver ends it. Otherwise it
/// is approved once one approver's distinct device keys reach the rule's
/// count (and, for a reserved class, the primary's `reserved_devices`).
/// Nobody approves a request they made.
///
/// What the caller owes:
/// - verify each submission when it arrives (`verify_approval`) and keep at
///   most one per device and decision, so `approvals` never grows with junk;
/// - pass `devices` as they are now, except each passkey's `sign_count`,
///   which is the one from when the request was made: revocations take
///   effect at once, and re-deciding with the same submissions gives the
///   same answer;
/// - store `sign_counts` afterwards, and latch Approved and Denied: once a
///   request is acted on, it is never acted on again.
pub fn decide(
    request: &ApprovalRequest,
    approvals: &[Approval],
    devices: &[ApproverDevice],
    rules: &[ApprovalRule],
    rp: &Primary,
    now: u64,
) -> Result<Decided, ApprovalError> {
    request.check(rp, now)?;
    let governing: Vec<&ApprovalRule> = request.governing_classes().into_iter().map(|class| rule_for(rules, class)).collect::<Result<_, _>>()?;
    let floor = if request.is_reserved() { usize::from(rp.reserved_devices.max(1)) } else { 1 };
    let need = governing.iter().map(|rule| usize::from(rule.devices.max(1))).max().unwrap_or(1).max(floor);
    // Which human each key has counted for: one key never counts for two.
    let mut key_owner: BTreeMap<String, &Name> = BTreeMap::new();
    let mut rejected = Vec::new();
    let mut sign_counts = BTreeMap::new();
    let mut denied = false;
    let mut keys: BTreeMap<&Name, BTreeSet<String>> = BTreeMap::new();
    for (index, approval) in approvals.iter().enumerate() {
        let (device, count) = match verify_approval(request, approval, devices, rp) {
            Ok(verified) => verified,
            Err(err) => {
                rejected.push((index, err));
                continue;
            }
        };
        if !governing.iter().all(|rule| rule.approvers.matches(&device.human)) {
            rejected.push((index, ApprovalError::NotAnApprover));
            continue;
        }
        if device.human == request.actor {
            rejected.push((index, ApprovalError::OwnRequest));
            continue;
        }
        let key = device.key_bytes();
        if key_owner.get(&key).is_some_and(|owner| *owner != &device.human) {
            rejected.push((index, ApprovalError::DuplicateKey));
            continue;
        }
        key_owner.insert(key, &device.human);
        if let Some(count) = count {
            let stored = sign_counts.entry(device.id.clone()).or_insert(count);
            *stored = (*stored).max(count);
        }
        match approval.decision {
            Decision::Deny => denied = true,
            Decision::Approve => {
                keys.entry(&device.human).or_default().insert(device.key_bytes());
            }
        }
    }
    let have = keys.values().map(BTreeSet::len).max().unwrap_or(0);
    let outcome = if denied {
        Outcome::Denied
    } else if have >= need {
        Outcome::Approved
    } else {
        Outcome::Pending { have, need }
    };
    Ok(Decided { outcome, rejected, sign_counts })
}

/// Whether a coordinator (an agent or service approving through its role
/// rather than a device) may approve this request. It may approve only the
/// classes a person enabled for it (`enabled`: classes or `prefix.*`), never a
/// reserved one, and never:
/// - anything that grants approver rights, so it can never make another
///   approver, and two coordinators can never promote each other;
/// - anything whose reach is unbounded, or touches itself or anything that
///   started it (no self-promotion; only a person widens what it holds);
/// - its own request, one from whoever it acts for, from anything that
///   started it or that it started, or from a sibling under the same agent.
///
/// Humans approve with a device and app users never approve. Its rate
/// limits, and checking its role allows `approve`, are the primary's.
pub fn delegation_allowed(request: &ApprovalRequest, approver: &Name, approver_chain: &[Name], enabled: &[String]) -> bool {
    let class_enabled = enabled.iter().any(|pattern| match pattern.strip_suffix(".*") {
        Some(prefix) => request.class.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('.')),
        None => pattern == &request.class,
    });
    let lineage = || std::iter::once(approver).chain(approver_chain);
    // Agents sharing an ancestor agent are one line. Services and brokers
    // that start everything don't count.
    let shared_agent = approver_chain.iter().any(|name| name.kind() == Kind::Agent && request.chain.contains(name));
    let self_promotion = matches!(request.affects, Reach::Unbounded) || lineage().any(|name| request.affects.touches(name));
    class_enabled
        && !request.is_reserved()
        && !shared_agent
        && !self_promotion
        && matches!(approver.kind(), Kind::Agent | Kind::Service)
        && approver.org() == &request.org
        && approver != &request.actor
        && request.act_for.as_ref() != Some(approver)
        && !request.chain.contains(approver)
        && !approver_chain.contains(&request.actor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;

    const NOW: u64 = 1_800_000_000;

    fn name(text: &str) -> Name {
        text.parse().unwrap()
    }

    fn rp() -> Primary {
        Primary { issuer: "https://account.addis.gg".into(), rp_id: "account.addis.gg".into(), reserved_devices: 1 }
    }

    fn request(class: &str) -> ApprovalRequest {
        ApprovalRequest {
            id: "ap_01jbx7q4m2k9z8w3v5t6h8n2".into(),
            primary: "https://account.addis.gg".into(),
            org: "gg.addis".parse().unwrap(),
            class: class.into(),
            actor: name("gg.addis.agent.ava"),
            act_for: Some(name("gg.addis.human.sami")),
            chain: vec![name("gg.addis.agent.orchestrator")],
            zone: Some(name("gg.addis.zone.vm-01jbx4k2m9q8r7s6")),
            action: Action::Token { audience: "https://api.simien.dev".into(), scopes: vec!["deploy:site".into()] },
            affects: Reach::None,
            grants_approval: false,
            created_at: NOW - 10,
            expires_at: NOW + 600,
        }
    }

    struct Device {
        key: SigningKey,
        device: ApproverDevice,
    }

    fn device(id: &str, human: &str, kind: DeviceKind) -> Device {
        with_key(id, human, kind, SigningKey::random(&mut rand_core::OsRng))
    }

    fn with_key(id: &str, human: &str, kind: DeviceKind, key: SigningKey) -> Device {
        let device = ApproverDevice {
            id: id.into(),
            human: name(human),
            kind,
            public_key: crate::oidc::es256_jwk(key.verifying_key()),
            credential_id: (kind == DeviceKind::Passkey).then(|| format!("cred-{id}")),
            enrolled_at: NOW - 100,
            user_verification: true,
            backup_eligible: false,
            sign_count: 0,
            revoked: false,
        };
        Device { key, device }
    }

    fn signed(device: &Device, request: &ApprovalRequest, decision: Decision) -> Approval {
        let signature: Signature = device.key.sign(&request.challenge(decision, &device.device.id));
        Approval {
            request_id: request.id.clone(),
            device_id: device.device.id.clone(),
            decision,
            proof: Proof::Signature { signature: B64URL.encode(signature.to_der().as_bytes()) },
        }
    }

    /// What a browser hands back from navigator.credentials.get(), with knobs
    /// for everything the check must refuse.
    struct Assertion<'a> {
        kind: &'a str,
        challenge: Option<[u8; 32]>,
        origin: &'a str,
        rp_id: &'a str,
        flags: u8,
        count: u32,
        extra: serde_json::Value,
    }

    impl Default for Assertion<'_> {
        fn default() -> Self {
            Assertion { kind: "webauthn.get", challenge: None, origin: "https://account.addis.gg", rp_id: "account.addis.gg", flags: 0x05, count: 7, extra: serde_json::json!({}) }
        }
    }

    fn passkey(device: &Device, request: &ApprovalRequest, decision: Decision, a: Assertion<'_>) -> Approval {
        let mut authenticator_data = Sha256::digest(a.rp_id.as_bytes()).to_vec();
        authenticator_data.push(a.flags);
        authenticator_data.extend_from_slice(&a.count.to_be_bytes());
        let mut client = serde_json::json!({
            "type": a.kind,
            "challenge": B64URL.encode(a.challenge.unwrap_or(request.challenge(decision, &device.device.id))),
            "origin": a.origin,
        });
        for (key, value) in a.extra.as_object().unwrap() {
            client[key] = value.clone();
        }
        let client_data_json = client.to_string();
        let mut message = authenticator_data.clone();
        message.extend_from_slice(&Sha256::digest(client_data_json.as_bytes()));
        let signature: Signature = device.key.sign(&message);
        Approval {
            request_id: request.id.clone(),
            device_id: device.device.id.clone(),
            decision,
            proof: Proof::WebAuthn {
                authenticator_data: B64URL.encode(&authenticator_data),
                client_data_json: B64URL.encode(client_data_json.as_bytes()),
                signature: B64URL.encode(signature.to_der().as_bytes()),
            },
        }
    }

    fn rules() -> Vec<ApprovalRule> {
        vec![
            ApprovalRule { class: "deploy.*".into(), approvers: "gg.addis.human.*".parse().unwrap(), devices: 1 },
            ApprovalRule { class: "policy.*".into(), approvers: "gg.addis.human.sami".parse().unwrap(), devices: 1 },
            ApprovalRule { class: "device.*".into(), approvers: "gg.addis.human.sami".parse().unwrap(), devices: 1 },
            ApprovalRule { class: "approvals.*".into(), approvers: "gg.addis.human.sami".parse().unwrap(), devices: 1 },
            ApprovalRule { class: "audit.*".into(), approvers: "gg.addis.human.sami".parse().unwrap(), devices: 1 },
            ApprovalRule { class: "trust.*".into(), approvers: "gg.addis.human.sami".parse().unwrap(), devices: 1 },
            ApprovalRule { class: "keys.*".into(), approvers: "gg.addis.human.sami".parse().unwrap(), devices: 1 },
        ]
    }

    fn outcome(ask: &ApprovalRequest, approvals: &[Approval], devices: &[ApproverDevice]) -> Result<Outcome, ApprovalError> {
        decide(ask, approvals, devices, &rules(), &rp(), NOW).map(|decided| decided.outcome)
    }

    fn rejected(ask: &ApprovalRequest, approvals: &[Approval], devices: &[ApproverDevice]) -> Vec<ApprovalError> {
        decide(ask, approvals, devices, &rules(), &rp(), NOW).unwrap().rejected.into_iter().map(|(_, err)| err).collect()
    }

    #[test]
    fn a_device_signature_over_the_request_approves_it() {
        let phone = device("phone-1", "gg.addis.human.sami", DeviceKind::Phone);
        let ask = request("deploy.production");
        let devices = [phone.device.clone()];
        assert_eq!(outcome(&ask, &[], &devices), Ok(Outcome::Pending { have: 0, need: 1 }));
        assert_eq!(outcome(&ask, &[signed(&phone, &ask, Decision::Approve)], &devices), Ok(Outcome::Approved));
        assert_eq!(outcome(&ask, &[signed(&phone, &ask, Decision::Deny)], &devices), Ok(Outcome::Denied));
    }

    #[test]
    fn the_signed_bytes_are_pinned_so_other_implementations_can_match_them() {
        // If this changes, every phone and passkey page must change with it:
        // bump the context string instead of editing the encoding in place.
        let hex = |digest: [u8; 32]| digest.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let mut affecting = request("policy.widen");
        affecting.affects = Reach::Actors(vec![name("gg.addis.agent.worker")]);
        assert_eq!(hex(affecting.challenge(Decision::Approve, "mac-1")), KNOWN_ANSWER_AFFECTS);
        assert_eq!(hex(request("deploy.production").challenge(Decision::Approve, "phone-1")), KNOWN_ANSWER);
        // Every optional absent, an empty chain, another kind of action, a deny.
        let mut bare = request("deploy.production");
        bare.act_for = None;
        bare.chain.clear();
        bare.zone = None;
        bare.action = Action::Read { path: "prod/site/DATABASE_URL".into() };
        assert_eq!(hex(bare.challenge(Decision::Deny, "pk-1")), KNOWN_ANSWER_BARE);
        let mut grant = request("deploy.production");
        grant.action = Action::Approve { class: "policy.narrow".into() };
        assert_eq!(hex(grant.challenge(Decision::Approve, "mac-1")), KNOWN_ANSWER_GRANT);
        let mut write = bare.clone();
        write.action = Action::Write { path: "prod/a".into() };
        assert_eq!(hex(write.challenge(Decision::Approve, "pk-1")), KNOWN_ANSWER_WRITE);
        let mut launch = bare;
        launch.action = Action::Launch { profile: name("gg.addis.profile.build-vm") };
        assert_eq!(hex(launch.challenge(Decision::Approve, "pk-1")), KNOWN_ANSWER_LAUNCH);
    }

    /// Computed by a separate Python script from the encoding written in
    /// `challenge`'s doc, not by this code, so the two had to agree.
    const KNOWN_ANSWER: &str = "8839b531ca3f90b3c37b5014c7df1eab7b2c963546b2b43dcf111f7b6b60ecc1";
    const KNOWN_ANSWER_AFFECTS: &str = "b7733ede4e6e7651d0c6a35237c0c1fb8e0bda2a84832ffedbbe9bad96ca0f0c";
    const KNOWN_ANSWER_GRANT: &str = "673fe65c2beb3aea4f13f0762ad615354a831cec965be3742776b52655646a01";
    const KNOWN_ANSWER_WRITE: &str = "4063400ce9215c7db1b7400e552a2bd59a08ffbc622492f97988892be8f566eb";
    const KNOWN_ANSWER_LAUNCH: &str = "c98aeabb767901fe02da79c47d7acde522d39ecfcf8876a33febb85d0d034b41";
    const KNOWN_ANSWER_BARE: &str = "e7de97f4c22bd87f62eaab7d67ca73c902cd3cb292d0fce61dc5fc90ee5e69fb";

    #[test]
    fn a_signature_fits_only_its_own_request_and_decision() {
        let phone = device("phone-1", "gg.addis.human.sami", DeviceKind::Phone);
        let devices = [phone.device.clone()];
        let ask = request("deploy.production");

        let mut flipped = signed(&phone, &ask, Decision::Deny);
        flipped.decision = Decision::Approve;
        assert_eq!(rejected(&ask, &[flipped], &devices), [ApprovalError::BadProof], "a deny relabelled as an approve");

        let approval = signed(&phone, &ask, Decision::Approve);
        type Change = Box<dyn Fn(&mut ApprovalRequest)>;
        let changes: Vec<(&str, Change)> = vec![
            ("class", Box::new(|r| r.class = "deploy.staging".into())),
            ("actor", Box::new(|r| r.actor = name("gg.addis.agent.eve"))),
            ("act_for", Box::new(|r| r.act_for = None)),
            ("chain", Box::new(|r| r.chain.clear())),
            ("zone", Box::new(|r| r.zone = None)),
            ("action", Box::new(|r| r.action = Action::Token { audience: "https://api.simien.dev".into(), scopes: vec!["deploy:*".into()] })),
            ("action kind", Box::new(|r| r.action = Action::Read { path: "prod/site/DATABASE_URL".into() })),
            ("affects", Box::new(|r| r.affects = Reach::Actors(vec![name("gg.addis.agent.worker")]))),
            ("affects kind", Box::new(|r| r.affects = Reach::Unbounded)),
            ("grants_approval", Box::new(|r| r.grants_approval = true)),
            ("created_at", Box::new(|r| r.created_at -= 1)),
            ("expires_at", Box::new(|r| r.expires_at += 1)),
        ];
        for (what, change) in changes {
            let mut other = ask.clone();
            change(&mut other);
            assert_eq!(rejected(&other, std::slice::from_ref(&approval), &devices), [ApprovalError::BadProof], "{what}");
        }
        // A copy for another primary, decided by that primary: still not this signature.
        let mut staging = ask.clone();
        staging.primary = "https://staging.addis.gg".into();
        let at_staging = Primary { issuer: staging.primary.clone(), ..rp() };
        let decided = decide(&staging, std::slice::from_ref(&approval), &devices, &rules(), &at_staging, NOW).unwrap();
        assert_eq!(decided.rejected, [(0, ApprovalError::BadProof)], "primary");
        // The same request under another id: its challenge differs too.
        let mut renamed = ask.clone();
        renamed.id = "ap_01jbx7q4m2k9z8w3v5t6h8n3".into();
        let mut moved = approval.clone();
        moved.request_id = renamed.id.clone();
        assert_eq!(rejected(&renamed, &[moved], &devices), [ApprovalError::BadProof], "id");
        // Another org's copy fails before any signature is checked.
        let mut elsewhere = ask.clone();
        elsewhere.org = "com.acme".parse().unwrap();
        assert_eq!(outcome(&elsewhere, std::slice::from_ref(&approval), &devices), Err(ApprovalError::BadRequest), "org");
    }

    #[test]
    fn what_a_device_shows_comes_from_the_signed_fields() {
        let ask = request("deploy.production");
        assert_eq!(
            ask.describe(),
            "[deploy.production gg.addis on https://account.addis.gg] gg.addis.agent.ava wants to get a token for \"https://api.simien.dev\" with scopes [\"deploy:site\"]; for gg.addis.human.sami; from gg.addis.zone.vm-01jbx4k2m9q8r7s6"
        );
        // Text that could read differently from what it is never gets that far.
        for path in ["prod/site/\u{202e}YEK", "prod/site/\nKEY", "", "prod/site/KEY, for gg.addis.human.sami", "prod/../x", "prod/site/KEY\"", "prod/site\\KEY"] {
            let mut sneaky = ask.clone();
            sneaky.action = Action::Read { path: path.into() };
            assert_eq!(outcome(&sneaky, &[], &[]), Err(ApprovalError::BadRequest), "{path:?}");
        }
        let sneaky_actions = [
            Action::Token { audience: "https://api.simien.dev with scopes [x]".into(), scopes: vec![] },
            Action::Token { audience: "https://api.simien.dev".into(), scopes: vec!["a, b".into()] },
            Action::Token { audience: "https://api.simien.dev".into(), scopes: (0..17).map(|n| format!("s{n}")).collect() },
            Action::Approve { class: "Not A Class".into() },
        ];
        for action in sneaky_actions {
            let mut sneaky = ask.clone();
            sneaky.action = action.clone();
            assert_eq!(outcome(&sneaky, &[], &[]), Err(ApprovalError::BadRequest), "{action:?}");
        }
        let mut launch = ask.clone();
        launch.action = Action::Launch { profile: name("gg.addis.agent.x") };
        assert_eq!(outcome(&launch, &[], &[]), Err(ApprovalError::BadRequest), "a launch must name a profile");
        launch.action = Action::Launch { profile: name("com.acme.profile.x") };
        assert_eq!(outcome(&launch, &[], &[]), Err(ApprovalError::BadRequest), "of this org");
        let mut wordy = ask.clone();
        wordy.action = Action::Token { audience: "https://api.simien.dev".into(), scopes: (0..5).map(|n| format!("s{n}{}", "x".repeat(240))).collect() };
        assert_eq!(outcome(&wordy, &[], &[]), Err(ApprovalError::BadRequest), "more than a device should be asked to show");
        let mut long_chain = ask.clone();
        long_chain.chain = (0..9).map(|n| name(&format!("gg.addis.agent.a{n}"))).collect();
        assert_eq!(outcome(&long_chain, &[], &[]), Err(ApprovalError::BadRequest), "chain capped");
    }

    #[test]
    fn passkeys_follow_webauthn_to_the_letter() {
        let pk = device("pk-1", "gg.addis.human.sami", DeviceKind::Passkey);
        let devices = [pk.device.clone()];
        let ask = request("deploy.production");
        let ok = passkey(&pk, &ask, Decision::Approve, Assertion::default());
        let decided = decide(&ask, &[ok], &devices, &rules(), &rp(), NOW).unwrap();
        assert_eq!(decided.outcome, Outcome::Approved);
        assert_eq!(decided.sign_counts.get("pk-1"), Some(&7), "the counter to store");

        let other = device("pk-other", "gg.addis.human.sami", DeviceKind::Passkey);
        let cases: Vec<(&str, Approval)> = vec![
            ("another origin", passkey(&pk, &ask, Decision::Approve, Assertion { origin: "https://evil.example", ..Assertion::default() })),
            ("another relying party", passkey(&pk, &ask, Decision::Approve, Assertion { rp_id: "evil.example", ..Assertion::default() })),
            ("not a get", passkey(&pk, &ask, Decision::Approve, Assertion { kind: "webauthn.create", ..Assertion::default() })),
            ("another challenge", passkey(&pk, &ask, Decision::Approve, Assertion { challenge: Some([0; 32]), ..Assertion::default() })),
            ("user not verified", passkey(&pk, &ask, Decision::Approve, Assertion { flags: 0x01, ..Assertion::default() })),
            ("user not present", passkey(&pk, &ask, Decision::Approve, Assertion { flags: 0x04, ..Assertion::default() })),
            ("inside another site's frame", passkey(&pk, &ask, Decision::Approve, Assertion { extra: serde_json::json!({"crossOrigin": true}), ..Assertion::default() })),
            ("with a top origin", passkey(&pk, &ask, Decision::Approve, Assertion { extra: serde_json::json!({"topOrigin": "https://evil.example"}), ..Assertion::default() })),
            ("signed by another key", {
                let mut approval = passkey(&other, &ask, Decision::Approve, Assertion::default());
                approval.device_id = "pk-1".into();
                approval
            }),
            ("a deny relabelled", {
                let mut approval = passkey(&pk, &ask, Decision::Deny, Assertion::default());
                approval.decision = Decision::Approve;
                approval
            }),
            ("a raw signature in a passkey's place", signed(&pk, &ask, Decision::Approve)),
        ];
        for (what, approval) in cases {
            assert_eq!(rejected(&ask, &[approval], &devices), [ApprovalError::BadProof], "{what}");
        }

        // The relying party comes from the primary, not the device record.
        let elsewhere = Primary { rp_id: "evil.example".into(), ..rp() };
        let forged = passkey(&pk, &ask, Decision::Approve, Assertion { origin: "https://evil.example", rp_id: "evil.example", ..Assertion::default() });
        assert_eq!(decide(&ask, std::slice::from_ref(&forged), &devices, &rules(), &rp(), NOW).unwrap().outcome, Outcome::Pending { have: 0, need: 1 });
        assert_eq!(decide(&ask, &[forged], &devices, &rules(), &elsewhere, NOW).unwrap().outcome, Outcome::Approved, "only when the primary itself is that site");
    }

    #[test]
    fn a_cloned_passkey_is_caught_by_its_counter() {
        let mut pk = device("pk-1", "gg.addis.human.sami", DeviceKind::Passkey);
        pk.device.sign_count = 7;
        let devices = [pk.device.clone()];
        let ask = request("deploy.production");
        let replayed = passkey(&pk, &ask, Decision::Approve, Assertion { count: 7, ..Assertion::default() });
        assert_eq!(rejected(&ask, &[replayed], &devices), [ApprovalError::BadProof], "a counter that didn't move");
        let ahead = passkey(&pk, &ask, Decision::Approve, Assertion { count: 8, ..Assertion::default() });
        assert_eq!(outcome(&ask, &[ahead], &devices), Ok(Outcome::Approved));
        let downgraded = passkey(&pk, &ask, Decision::Approve, Assertion { count: 0, ..Assertion::default() });
        assert_eq!(rejected(&ask, &[downgraded], &devices), [ApprovalError::BadProof], "a counter that went back to 0");
        // Two assertions from one device: the higher counter is the one kept.
        let both = [
            passkey(&pk, &ask, Decision::Approve, Assertion { count: 9, ..Assertion::default() }),
            passkey(&pk, &ask, Decision::Approve, Assertion { count: 8, ..Assertion::default() }),
        ];
        assert_eq!(decide(&ask, &both, &devices, &rules(), &rp(), NOW).unwrap().sign_counts.get("pk-1"), Some(&9));
        // Synced passkeys always say 0, and that's allowed when we've only seen 0.
        let synced = device("pk-2", "gg.addis.human.sami", DeviceKind::Passkey);
        let zero = passkey(&synced, &ask, Decision::Approve, Assertion { count: 0, ..Assertion::default() });
        assert_eq!(outcome(&ask, &[zero], std::slice::from_ref(&synced.device)), Ok(Outcome::Approved));
    }

    #[test]
    fn reserved_classes_need_the_configured_devices_and_never_a_synced_passkey() {
        let phone = device("phone-1", "gg.addis.human.sami", DeviceKind::Phone);
        let mac = device("mac-1", "gg.addis.human.sami", DeviceKind::Mac);
        let devices = [phone.device.clone(), mac.device.clone()];
        let two = Primary { reserved_devices: 2, ..rp() };
        for class in ["device.enroll", "approvals.rules", "audit.change", "trust.change", "keys.rotate"] {
            let ask = request(class);
            assert!(ask.is_reserved(), "{class}");
            let once = signed(&phone, &ask, Decision::Approve);
            assert_eq!(outcome(&ask, std::slice::from_ref(&once), &devices), Ok(Outcome::Approved), "{class}: one device, the default");
            let with_two = |approvals: &[Approval]| decide(&ask, approvals, &devices, &rules(), &two, NOW).map(|d| d.outcome);
            assert_eq!(with_two(std::slice::from_ref(&once)), Ok(Outcome::Pending { have: 1, need: 2 }), "{class}: set to two");
            assert_eq!(with_two(&[once.clone(), once.clone()]), Ok(Outcome::Pending { have: 1, need: 2 }), "{class}: one device twice");
            assert_eq!(with_two(&[once, signed(&mac, &ask, Decision::Approve)]), Ok(Outcome::Approved), "{class}");
        }
        assert!(!request("policy.widen").is_reserved(), "widening policy is a coordinator's to approve");

        // One key enrolled under two ids is still one key.
        let twin = with_key("mac-2", "gg.addis.human.sami", DeviceKind::Mac, phone.key.clone());
        let ask = request("keys.rotate");
        let both = [phone.device.clone(), twin.device.clone()];
        let decided = decide(&ask, &[signed(&phone, &ask, Decision::Approve), signed(&twin, &ask, Decision::Approve)], &both, &rules(), &two, NOW).unwrap();
        assert_eq!(decided.outcome, Outcome::Pending { have: 1, need: 2 });

        // A synced passkey can approve a deploy, never a reserved class.
        let mut synced = device("pk-1", "gg.addis.human.sami", DeviceKind::Passkey);
        synced.device.backup_eligible = true;
        let deploy = request("deploy.production");
        assert_eq!(outcome(&deploy, &[passkey(&synced, &deploy, Decision::Approve, Assertion::default())], std::slice::from_ref(&synced.device)), Ok(Outcome::Approved));
        let enroll = request("device.enroll");
        assert_eq!(rejected(&enroll, &[passkey(&synced, &enroll, Decision::Approve, Assertion::default())], std::slice::from_ref(&synced.device)), [ApprovalError::SyncedPasskey]);
        let flagged = device("pk-2", "gg.addis.human.sami", DeviceKind::Passkey);
        let says_synced = passkey(&flagged, &enroll, Decision::Approve, Assertion { flags: 0x0d, ..Assertion::default() });
        assert_eq!(rejected(&enroll, &[says_synced], std::slice::from_ref(&flagged.device)), [ApprovalError::SyncedPasskey], "the BE flag on the assertion counts too");
        let backed_up = passkey(&flagged, &enroll, Decision::Approve, Assertion { flags: 0x15, ..Assertion::default() });
        assert_eq!(rejected(&enroll, &[backed_up], std::slice::from_ref(&flagged.device)), [ApprovalError::SyncedPasskey], "and so does BS");

        // Granting approver rights is reserved, whatever its class says.
        let mut grant = request("deploy.staging");
        grant.action = Action::Approve { class: "policy.widen".into() };
        assert!(grant.is_reserved());
        assert!(!delegation_allowed(&grant, &name("gg.addis.agent.helper"), &[], &["deploy.*".into()]));
        let mut synced_grant = device("pk-9", "gg.addis.human.sami", DeviceKind::Passkey);
        synced_grant.device.backup_eligible = true;
        assert_eq!(rejected(&grant, &[passkey(&synced_grant, &grant, Decision::Approve, Assertion::default())], std::slice::from_ref(&synced_grant.device)), [ApprovalError::SyncedPasskey], "nor by a synced passkey");

        // A grant is also judged by the rule for what it grants: eve may approve
        // deploys, but only sami may approve anything that hands out policy rights.
        let eve = device("eve-1", "gg.addis.human.eve", DeviceKind::Phone);
        assert_eq!(rejected(&grant, &[signed(&eve, &grant, Decision::Approve)], std::slice::from_ref(&eve.device)), [ApprovalError::NotAnApprover]);
    }

    #[test]
    fn classes_are_checked_and_the_closest_rule_governs() {
        assert_eq!(outcome(&request("Policy.widen"), &[], &[]), Err(ApprovalError::BadRequest));
        assert_eq!(outcome(&request("policy.widen "), &[], &[]), Err(ApprovalError::BadRequest));
        assert_eq!(outcome(&request("policy..widen"), &[], &[]), Err(ApprovalError::BadRequest));
        assert_eq!(outcome(&request("unknown.class"), &[], &[]), Err(ApprovalError::NoRule));

        let loose = ApprovalRule { class: "deploy.*".into(), approvers: "gg.addis.human.*".parse().unwrap(), devices: 1 };
        let strict = ApprovalRule { class: "deploy.production".into(), approvers: "gg.addis.human.sami".parse().unwrap(), devices: 2 };
        for order in [vec![loose.clone(), strict.clone()], vec![strict.clone(), loose.clone()]] {
            assert_eq!(rule_for(&order, "deploy.production"), Ok(&strict), "exact beats a prefix, in any order");
            assert_eq!(rule_for(&order, "deploy.staging"), Ok(&loose));
        }
        let deeper = ApprovalRule { class: "deploy.production.*".into(), ..loose.clone() };
        assert_eq!(rule_for(&[loose.clone(), deeper.clone()], "deploy.production.eu"), Ok(&deeper), "a longer prefix beats a shorter one");
        assert_eq!(rule_for(&[loose.clone(), loose.clone()], "deploy.x"), Err(ApprovalError::AmbiguousRules));
        assert_eq!(rule_for(&[loose], "deployx"), Err(ApprovalError::NoRule), "deploy.* doesn't cover deployx");
    }

    #[test]
    fn junk_submissions_change_nothing() {
        let phone = device("phone-1", "gg.addis.human.sami", DeviceKind::Phone);
        let eve = device("phone-eve", "gg.addis.human.eve", DeviceKind::Phone);
        let devices = [phone.device.clone(), eve.device.clone()];
        let ask = request("policy.narrow");
        let garbage = Approval { request_id: ask.id.clone(), device_id: "phone-1".into(), decision: Decision::Approve, proof: Proof::Signature { signature: "AAAA".into() } };
        let real = signed(&phone, &ask, Decision::Approve);
        let decided = decide(&ask, &[garbage.clone(), real], &devices, &rules(), &rp(), NOW).unwrap();
        assert_eq!(decided.outcome, Outcome::Approved, "junk ahead of a real approval doesn't block it");
        assert_eq!(decided.rejected, [(0, ApprovalError::BadProof)]);

        // eve isn't an approver for policy.*: her deny is set aside, not a veto.
        let eves_deny = signed(&eve, &ask, Decision::Deny);
        assert_eq!(outcome(&ask, &[eves_deny], &devices), Ok(Outcome::Pending { have: 0, need: 1 }));
        // And junk can't hide a real deny either.
        assert_eq!(outcome(&ask, &[garbage, signed(&phone, &ask, Decision::Deny)], &devices), Ok(Outcome::Denied));
    }

    #[test]
    fn devices_must_be_enrolled_before_the_request_live_verified_and_allowed() {
        let phone = device("phone-1", "gg.addis.human.sami", DeviceKind::Phone);
        let ask = request("policy.narrow");
        let approval = signed(&phone, &ask, Decision::Approve);
        let with = |change: &dyn Fn(&mut ApproverDevice)| {
            let mut device = phone.device.clone();
            change(&mut device);
            rejected(&ask, std::slice::from_ref(&approval), &[device])
        };
        assert_eq!(rejected(&ask, std::slice::from_ref(&approval), &[]), [ApprovalError::UnknownDevice]);
        assert_eq!(with(&|d| d.revoked = true), [ApprovalError::DeviceRevoked]);
        assert_eq!(with(&|d| d.enrolled_at = ask.created_at), [ApprovalError::DeviceTooNew], "enrolled after the request was made");
        assert_eq!(with(&|d| d.user_verification = false), [ApprovalError::DeviceUnverified], "a key that signs without asking");
        assert_eq!(with(&|d| d.human = name("com.acme.human.sami")), [ApprovalError::NotAnApprover], "another org's human");
        assert_eq!(with(&|d| d.human = name("gg.addis.agent.sami")), [ApprovalError::NotAnApprover], "not a human");
        assert_eq!(with(&|d| d.public_key.crv = "P-384".into()), [ApprovalError::BadProof]);
        let impostor = device("phone-1", "gg.addis.human.sami", DeviceKind::Phone);
        assert_eq!(rejected(&ask, &[signed(&impostor, &ask, Decision::Approve)], std::slice::from_ref(&phone.device)), [ApprovalError::BadProof], "a key that isn't the one enrolled");
        let stranger = device("phone-2", "gg.addis.human.eve", DeviceKind::Phone);
        assert_eq!(rejected(&ask, &[signed(&stranger, &ask, Decision::Approve)], std::slice::from_ref(&stranger.device)), [ApprovalError::NotAnApprover], "policy.* is sami's alone");
    }

    #[test]
    fn requests_are_short_lived_and_well_formed() {
        let mut late = request("deploy.production");
        late.expires_at = NOW;
        assert_eq!(outcome(&late, &[], &[]), Err(ApprovalError::Expired));
        let mut long = request("deploy.production");
        long.expires_at = long.created_at + MAX_REQUEST_SECONDS + 1;
        assert_eq!(outcome(&long, &[], &[]), Err(ApprovalError::BadRequest), "a year-long window");
        let mut future = request("deploy.production");
        future.created_at = NOW + 3600;
        future.expires_at = NOW + 3700;
        assert_eq!(outcome(&future, &[], &[]), Err(ApprovalError::BadRequest), "made in the future");
        let mut short_id = request("deploy.production");
        short_id.id = "ap_1".into();
        assert_eq!(outcome(&short_id, &[], &[]), Err(ApprovalError::BadRequest), "ids are long and random");
        let mut backwards = request("deploy.production");
        backwards.expires_at = backwards.created_at;
        assert_eq!(outcome(&backwards, &[], &[]), Err(ApprovalError::BadRequest), "expires before it was made");
        type Change = Box<dyn Fn(&mut ApprovalRequest)>;
        let foreign: [Change; 3] = [
            Box::new(|r| r.zone = Some(name("com.acme.zone.x"))),
            Box::new(|r| r.act_for = Some(name("com.acme.human.x"))),
            Box::new(|r| r.chain = vec![name("com.acme.agent.x")]),
        ];
        for change in foreign {
            let mut other = request("deploy.production");
            change(&mut other);
            assert_eq!(outcome(&other, &[], &[]), Err(ApprovalError::BadRequest), "every name in the request is the org's");
        }
        let mut zone_as_actor = request("deploy.production");
        zone_as_actor.actor = name("gg.addis.zone.demon");
        assert_eq!(outcome(&zone_as_actor, &[], &[]), Err(ApprovalError::BadRequest), "the actor must be an actor");
        let mut role_for = request("deploy.production");
        role_for.act_for = Some(name("gg.addis.role.admin"));
        assert_eq!(outcome(&role_for, &[], &[]), Err(ApprovalError::BadRequest), "acting for a person, never a role");
        let mut zone_in_chain = request("deploy.production");
        zone_in_chain.chain = vec![name("gg.addis.zone.demon")];
        assert_eq!(outcome(&zone_in_chain, &[], &[]), Err(ApprovalError::BadRequest));
        let mut not_a_zone = request("deploy.production");
        not_a_zone.zone = Some(name("gg.addis.agent.x"));
        assert_eq!(outcome(&not_a_zone, &[], &[]), Err(ApprovalError::BadRequest));
        let mut spaced = request("deploy.production");
        spaced.id = "ap_01jbx7q4m2k9z8w3v5t6h8n 2".into();
        assert_eq!(outcome(&spaced, &[], &[]), Err(ApprovalError::BadRequest));
        let mut elsewhere = request("deploy.production");
        elsewhere.primary = "https://staging.addis.gg".into();
        assert_eq!(outcome(&elsewhere, &[], &[]), Err(ApprovalError::BadRequest), "a request for another primary");
    }

    #[test]
    fn nobody_approves_their_own_request() {
        let phone = device("phone-1", "gg.addis.human.sami", DeviceKind::Phone);
        let mut ask = request("deploy.production");
        ask.actor = name("gg.addis.human.sami");
        ask.act_for = None;
        assert_eq!(rejected(&ask, &[signed(&phone, &ask, Decision::Approve)], std::slice::from_ref(&phone.device)), [ApprovalError::OwnRequest]);
    }

    #[test]
    fn a_coordinator_approves_real_work_but_never_reserved_classes_or_its_own_line() {
        let helper = name("gg.addis.agent.helper");
        let enabled = || vec!["deploy.*".to_string(), "policy.widen".to_string(), "broker.request".to_string()];
        let allowed = |request: &ApprovalRequest, approver: &Name| delegation_allowed(request, approver, &[], &enabled());
        let widen = |reach: Reach| ApprovalRequest { affects: reach, ..request("policy.widen") };
        assert!(allowed(&request("deploy.staging"), &helper));
        assert!(allowed(&request("deploy.production"), &helper), "a coordinator can do real work");
        assert!(allowed(&widen(Reach::Actors(vec![name("gg.addis.agent.worker")])), &helper), "including widening other agents' reach");
        assert!(allowed(&widen(Reach::Patterns(vec!["gg.addis.service.*".parse().unwrap()])), &helper), "or every service's");

        // Only what a person switched on; typos and unknown classes fail closed.
        assert!(!allowed(&request("policy.narrow.x"), &helper), "not enabled");
        assert!(!delegation_allowed(&request("deploy.staging"), &helper, &[], &[]), "nothing enabled, nothing approved");
        for reserved in ["device.enroll", "approvals.rules", "audit.change", "trust.change", "keys.rotate", "recovery.codes", "setup.link", "hosts.enroll", "issuer.change", "store.restore", "policy.rollback"] {
            assert!(!delegation_allowed(&request(reserved), &helper, &[], &[reserved.to_string()]), "{reserved} is a person's alone, even if enabled");
        }

        // No self-promotion: nothing that gives more to itself or its lineage,
        // by name, by a pattern that matches it, or by a reach nobody can bound.
        assert!(!allowed(&widen(Reach::Actors(vec![helper.clone()])), &helper), "itself");
        assert!(!allowed(&widen(Reach::Patterns(vec!["gg.addis.agent.*".parse().unwrap()])), &helper), "a pattern that matches it");
        assert!(!allowed(&widen(Reach::Unbounded), &helper), "a reach the primary can't bound");
        let boss = name("gg.addis.agent.boss");
        assert!(!delegation_allowed(&widen(Reach::Actors(vec![boss.clone()])), &helper, std::slice::from_ref(&boss), &enabled()), "what started it");

        // Two coordinators can't promote each other: making a second approver
        // is granting approver rights, which only a person approves.
        let make_coordinator = ApprovalRequest { grants_approval: true, ..widen(Reach::Actors(vec![name("gg.addis.agent.n")])) };
        assert!(make_coordinator.is_reserved());
        assert!(!allowed(&make_coordinator, &helper), "A can't make N an approver");

        assert!(!allowed(&request("deploy.staging"), &name("gg.addis.agent.ava")), "the asker");
        assert!(!allowed(&request("deploy.staging"), &name("gg.addis.agent.orchestrator")), "what started the asker");
        assert!(!allowed(&request("deploy.staging"), &name("gg.addis.human.sami")), "humans approve with a device");
        assert!(!allowed(&request("deploy.staging"), &name("gg.addis.user.u-1")), "app users never approve");
        assert!(!allowed(&request("deploy.staging"), &name("com.acme.agent.helper")), "another org");
        let mut for_agent = request("deploy.staging");
        for_agent.act_for = None;
        for_agent.actor = name("gg.addis.agent.ava");
        assert!(allowed(&for_agent, &helper));
        assert!(!delegation_allowed(&request("deploy.staging"), &helper, &[name("gg.addis.agent.ava")], &enabled()), "something the asker started");
        assert!(!delegation_allowed(&request("deploy.staging"), &helper, &[name("gg.addis.agent.orchestrator")], &enabled()), "a sibling under the same agent");
        assert!(delegation_allowed(&request("deploy.staging"), &helper, &[name("gg.addis.service.gild")], &enabled()), "a service that starts everything isn't a shared line");
    }

    #[test]
    fn reserved_names_match_on_whole_segments_and_malformed_classes_count_as_reserved() {
        assert!(is_reserved("device.enroll.extra"));
        assert!(!is_reserved("devices.enroll"), "a different root");
        assert!(!is_reserved("keysmith.x"));
        assert!(is_reserved("policy.rollback.v1"));
        assert!(!is_reserved("policy.rollbacks"));
        for malformed in ["Device.enroll", "device..x", " device.enroll", "", "deploy.production "] {
            assert!(is_reserved(malformed), "{malformed:?}");
        }
    }

    #[test]
    fn whose_reach_widens_is_shown_and_checked() {
        let mut ask = request("policy.widen");
        ask.affects = Reach::Patterns(vec!["gg.addis.agent.*".parse().unwrap()]);
        assert!(ask.describe().ends_with("; gives more to anything matching gg.addis.agent.*"), "{}", ask.describe());
        ask.affects = Reach::Unbounded;
        assert!(ask.describe().ends_with("; gives more to an unknown set"));
        ask.grants_approval = true;
        assert!(ask.describe().ends_with("; grants approver rights"));
        for bad in [Reach::Actors(vec![]), Reach::Actors(vec![name("com.acme.agent.x")]), Reach::Patterns(vec!["gg.addis.zone.*".parse().unwrap()])] {
            let mut other = request("policy.widen");
            other.affects = bad.clone();
            assert_eq!(outcome(&other, &[], &[]), Err(ApprovalError::BadRequest), "{bad:?}");
        }
    }

    #[test]
    fn deciding_again_with_the_same_submissions_gives_the_same_answer() {
        let mut pk = device("pk-1", "gg.addis.human.sami", DeviceKind::Passkey);
        pk.device.sign_count = 3;
        let mac = device("mac-1", "gg.addis.human.sami", DeviceKind::Mac);
        let devices = [pk.device.clone(), mac.device.clone()];
        let ask = request("keys.rotate");
        let two = Primary { reserved_devices: 2, ..rp() };
        let outcome = |ask: &ApprovalRequest, approvals: &[Approval], devices: &[ApproverDevice]| decide(ask, approvals, devices, &rules(), &two, NOW).map(|d| d.outcome);
        let first = passkey(&pk, &ask, Decision::Approve, Assertion { count: 4, ..Assertion::default() });
        assert_eq!(outcome(&ask, std::slice::from_ref(&first), &devices), Ok(Outcome::Pending { have: 1, need: 2 }));
        // The second device arrives later; the devices passed are still the
        // snapshot from when the request was made, so the passkey still counts.
        let both = [first, signed(&mac, &ask, Decision::Approve)];
        assert_eq!(outcome(&ask, &both, &devices), Ok(Outcome::Approved));
    }

    #[test]
    fn a_signature_counts_for_its_own_device_and_one_key_for_one_human() {
        let phone = device("phone-1", "gg.addis.human.sami", DeviceKind::Phone);
        let ask = request("deploy.production");
        // Sami's signature presented as coming from another record holding the same key.
        let copy = with_key("phone-copy", "gg.addis.human.eve", DeviceKind::Phone, phone.key.clone());
        let mut moved = signed(&phone, &ask, Decision::Approve);
        moved.device_id = "phone-copy".into();
        assert_eq!(rejected(&ask, &[moved], &[phone.device.clone(), copy.device.clone()]), [ApprovalError::BadProof], "the device id is signed");
        // One key enrolled for two humans counts for the first only.
        let both = [signed(&phone, &ask, Decision::Approve), signed(&copy, &ask, Decision::Approve)];
        assert_eq!(rejected(&ask, &both, &[phone.device.clone(), copy.device.clone()]), [ApprovalError::DuplicateKey]);
    }
}
