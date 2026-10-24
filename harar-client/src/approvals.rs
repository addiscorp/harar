//! Approvals (architecture, section 6): a human approves from a device that
//! signs only after Face ID, Touch ID or a PIN, over the exact request, so a
//! signature can't be replayed onto anything else. Machines and agents may
//! approve only classes their role names, never the highest ones, and never
//! their own requests.

use crate::model::{Action, Kind, Name, NamePattern, Org};
use crate::Jwk;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const CHALLENGE_CONTEXT: &[u8] = b"harar.approval.v1";

/// Classes that always need two of the approver's devices, and that no
/// machine or agent may ever approve.
pub const HIGHEST_CLASSES: [&str; 2] = ["policy.widen", "device.enroll"];

fn is_highest(class: &str) -> bool {
    HIGHEST_CLASSES.contains(&class)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceKind {
    /// The Secure Enclave key `harar agent` uses.
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
    /// For passkeys: the relying party the credential belongs to, e.g. `id.simien.dev`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    pub enrolled_at: u64,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Approve,
    Deny,
}

/// Something waiting for a person. Everything a device shows is in here,
/// and all of it is signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub org: Org,
    pub class: String,
    /// Who is asking.
    pub actor: Name,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act_for: Option<Name>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<Name>,
    pub action: Action,
    /// What the device shows, e.g. "Deploy addiscorp/site 4e1a9c0 to production".
    pub summary: String,
    pub created_at: u64,
    pub expires_at: u64,
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

impl ApprovalRequest {
    /// The 32 bytes a device signs: every field of the request and the
    /// decision, so an approval can't be turned into another request's, or a
    /// deny into an approve.
    pub fn challenge(&self, decision: Decision) -> [u8; 32] {
        let mut out = CHALLENGE_CONTEXT.to_vec();
        let action = serde_json::to_vec(&self.action).expect("actions serialize");
        let optional = |name: &Option<Name>| name.as_ref().map(|name| name.to_string()).unwrap_or_default();
        for part in [
            self.id.as_bytes(),
            self.org.as_str().as_bytes(),
            self.class.as_bytes(),
            self.actor.to_string().as_bytes(),
            optional(&self.act_for).as_bytes(),
            optional(&self.zone).as_bytes(),
            &action,
            self.summary.as_bytes(),
        ] {
            field(&mut out, part);
        }
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.push(match decision {
            Decision::Approve => 1,
            Decision::Deny => 0,
        });
        Sha256::digest(&out).into()
    }
}

/// How a device proved it signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Proof {
    /// Mac and phone: ECDSA P-256 over the challenge, DER, base64url.
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

/// Who may approve a class, and how many of their devices it takes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRule {
    /// A class, or a prefix ending in `*`.
    pub class: String,
    /// Humans who may approve.
    pub approvers: NamePattern,
    /// How many of one approver's devices must agree (at least 1; the highest
    /// classes always need 2).
    pub devices: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Approved,
    Denied,
    Pending { have: usize, need: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalError {
    Expired,
    NoRule,
    WrongRequest,
    UnknownDevice,
    DeviceRevoked,
    NotAnApprover,
    OwnRequest,
    BadProof,
}

impl ApprovalError {
    pub fn as_str(self) -> &'static str {
        match self {
            ApprovalError::Expired => "expired",
            ApprovalError::NoRule => "no_rule_for_class",
            ApprovalError::WrongRequest => "wrong_request",
            ApprovalError::UnknownDevice => "unknown_device",
            ApprovalError::DeviceRevoked => "device_revoked",
            ApprovalError::NotAnApprover => "not_an_approver",
            ApprovalError::OwnRequest => "own_request",
            ApprovalError::BadProof => "bad_proof",
        }
    }
}

fn class_matches(pattern: &str, class: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => class.starts_with(prefix),
        None => pattern == class,
    }
}

fn decode(value: &str) -> Result<Vec<u8>, ApprovalError> {
    B64URL.decode(value).map_err(|_| ApprovalError::BadProof)
}

fn verifying_key(device: &ApproverDevice) -> Result<VerifyingKey, ApprovalError> {
    crate::oidc::es256_verifying_key(&device.public_key).map_err(|_| ApprovalError::BadProof)
}

/// Checks a WebAuthn assertion: the client data is a `webauthn.get` for this
/// challenge from the relying party's own origin; the authenticator data is
/// for that relying party, with the user present and verified; and the
/// signature covers both.
fn verify_webauthn(
    key: &VerifyingKey,
    rp_id: &str,
    challenge: &[u8; 32],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
) -> Result<(), ApprovalError> {
    #[derive(Deserialize)]
    struct ClientData {
        #[serde(rename = "type")]
        kind: String,
        challenge: String,
        origin: String,
    }
    let client: ClientData = serde_json::from_slice(client_data_json).map_err(|_| ApprovalError::BadProof)?;
    if client.kind != "webauthn.get" || client.challenge != B64URL.encode(challenge) || client.origin != format!("https://{rp_id}") {
        return Err(ApprovalError::BadProof);
    }
    // rpIdHash (32) | flags (1) | signCount (4) | …
    if authenticator_data.len() < 37 || authenticator_data[..32] != Sha256::digest(rp_id.as_bytes())[..] {
        return Err(ApprovalError::BadProof);
    }
    let flags = authenticator_data[32];
    const USER_PRESENT: u8 = 0x01;
    const USER_VERIFIED: u8 = 0x04;
    if flags & USER_PRESENT == 0 || flags & USER_VERIFIED == 0 {
        return Err(ApprovalError::BadProof);
    }
    let mut signed = authenticator_data.to_vec();
    signed.extend_from_slice(&Sha256::digest(client_data_json));
    let signature = Signature::from_der(signature).map_err(|_| ApprovalError::BadProof)?;
    key.verify(&signed, &signature).map_err(|_| ApprovalError::BadProof)
}

/// Checks one approval: its device, its proof over this request and decision.
/// Returns the human it approves as.
pub fn verify_approval<'a>(
    request: &ApprovalRequest,
    approval: &Approval,
    devices: &'a [ApproverDevice],
) -> Result<&'a ApproverDevice, ApprovalError> {
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
    let key = verifying_key(device)?;
    let challenge = request.challenge(approval.decision);
    match (&approval.proof, device.kind) {
        (Proof::Signature { signature }, DeviceKind::Mac | DeviceKind::Phone) => {
            let signature = Signature::from_der(&decode(signature)?).map_err(|_| ApprovalError::BadProof)?;
            key.verify(&challenge, &signature).map_err(|_| ApprovalError::BadProof)?;
        }
        (Proof::WebAuthn { authenticator_data, client_data_json, signature }, DeviceKind::Passkey) => {
            let rp_id = device.rp_id.as_deref().ok_or(ApprovalError::BadProof)?;
            verify_webauthn(&key, rp_id, &challenge, &decode(authenticator_data)?, &decode(client_data_json)?, &decode(signature)?)?;
        }
        _ => return Err(ApprovalError::BadProof),
    }
    Ok(device)
}

/// Where a request stands, given every approval received for it. A valid
/// deny from any allowed approver ends it. Otherwise it is approved once one
/// approver's devices reach the rule's count (two, for the highest classes).
/// Nobody approves a request they made.
pub fn decide(
    request: &ApprovalRequest,
    approvals: &[Approval],
    devices: &[ApproverDevice],
    rules: &[ApprovalRule],
    now: u64,
) -> Result<Outcome, ApprovalError> {
    if now >= request.expires_at {
        return Err(ApprovalError::Expired);
    }
    let rule = rules.iter().find(|rule| class_matches(&rule.class, &request.class)).ok_or(ApprovalError::NoRule)?;
    let need = usize::from(rule.devices.max(1)).max(if is_highest(&request.class) { 2 } else { 1 });
    let mut approving: Vec<(&Name, BTreeSet<&str>)> = Vec::new();
    for approval in approvals {
        let device = verify_approval(request, approval, devices)?;
        if !rule.approvers.matches(&device.human) {
            return Err(ApprovalError::NotAnApprover);
        }
        if device.human == request.actor {
            return Err(ApprovalError::OwnRequest);
        }
        match approval.decision {
            Decision::Deny => return Ok(Outcome::Denied),
            Decision::Approve => match approving.iter_mut().find(|(human, _)| *human == &device.human) {
                Some((_, ids)) => {
                    ids.insert(device.id.as_str());
                }
                None => approving.push((&device.human, BTreeSet::from([device.id.as_str()]))),
            },
        }
    }
    let have = approving.iter().map(|(_, ids)| ids.len()).max().unwrap_or(0);
    Ok(if have >= need { Outcome::Approved } else { Outcome::Pending { have, need } })
}

/// Whether a machine or agent, approving through its role rather than a
/// device, may approve this request: the class is never one of the highest,
/// the approver is an agent or service (humans approve with a device; app
/// users never), and it is not the one asking nor the one the asker acts for.
/// Whether its role allows `approve <class>` is `Policy::decide`'s call.
pub fn delegation_allowed(request: &ApprovalRequest, approver: &Name) -> bool {
    !is_highest(&request.class)
        && matches!(approver.kind(), Kind::Agent | Kind::Service)
        && approver != &request.actor
        && request.act_for.as_ref() != Some(approver)
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

    fn request(class: &str) -> ApprovalRequest {
        ApprovalRequest {
            id: "ap_01jbx7".into(),
            org: "gg.addis".parse().unwrap(),
            class: class.into(),
            actor: name("gg.addis.agent.ava"),
            act_for: Some(name("gg.addis.human.sami")),
            zone: Some(name("gg.addis.zone.vm-01jbx4k2m9q8r7s6")),
            action: Action::Token { audience: "https://api.simien.dev".into(), scopes: vec!["deploy:site".into()] },
            summary: "Deploy addiscorp/site 4e1a9c0 to production".into(),
            created_at: NOW - 10,
            expires_at: NOW + 600,
        }
    }

    struct Device {
        key: SigningKey,
        device: ApproverDevice,
    }

    fn device(id: &str, human: &str, kind: DeviceKind) -> Device {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let public_key = crate::oidc::es256_jwk(key.verifying_key());
        let rp_id = (kind == DeviceKind::Passkey).then(|| "id.simien.dev".to_string());
        Device { device: ApproverDevice { id: id.into(), human: name(human), kind, public_key, rp_id, enrolled_at: NOW - 100, revoked: false }, key }
    }

    fn signed(device: &Device, request: &ApprovalRequest, decision: Decision) -> Approval {
        let signature: Signature = device.key.sign(&request.challenge(decision));
        Approval {
            request_id: request.id.clone(),
            device_id: device.device.id.clone(),
            decision,
            proof: Proof::Signature { signature: B64URL.encode(signature.to_der().as_bytes()) },
        }
    }

    /// What a browser hands back from navigator.credentials.get().
    fn passkey(device: &Device, request: &ApprovalRequest, decision: Decision, origin: &str, flags: u8) -> Approval {
        let rp_id = device.device.rp_id.clone().unwrap();
        let mut authenticator_data = Sha256::digest(rp_id.as_bytes()).to_vec();
        authenticator_data.push(flags);
        authenticator_data.extend_from_slice(&7_u32.to_be_bytes());
        let client_data_json = serde_json::json!({
            "type": "webauthn.get",
            "challenge": B64URL.encode(request.challenge(decision)),
            "origin": origin,
        })
        .to_string();
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
        ]
    }

    #[test]
    fn a_device_signature_over_the_request_approves_it() {
        let phone = device("phone-1", "gg.addis.human.sami", DeviceKind::Phone);
        let ask = request("deploy.production");
        let devices = [phone.device.clone()];
        assert_eq!(decide(&ask, &[], &devices, &rules(), NOW), Ok(Outcome::Pending { have: 0, need: 1 }));
        assert_eq!(decide(&ask, &[signed(&phone, &ask, Decision::Approve)], &devices, &rules(), NOW), Ok(Outcome::Approved));
        assert_eq!(decide(&ask, &[signed(&phone, &ask, Decision::Deny)], &devices, &rules(), NOW), Ok(Outcome::Denied));
    }

    #[test]
    fn a_signature_fits_only_its_own_request_and_decision() {
        let phone = device("phone-1", "gg.addis.human.sami", DeviceKind::Phone);
        let devices = [phone.device.clone()];
        let ask = request("deploy.production");

        // A deny's signature relabelled as an approve.
        let mut flipped = signed(&phone, &ask, Decision::Deny);
        flipped.decision = Decision::Approve;
        assert_eq!(decide(&ask, &[flipped], &devices, &rules(), NOW), Err(ApprovalError::BadProof));

        // An approval for one request presented for a request that differs in any field.
        let approval = signed(&phone, &ask, Decision::Approve);
        let mut others = Vec::new();
        for change in 0..6 {
            let mut other = ask.clone();
            match change {
                0 => other.summary = "Deploy addiscorp/site 4e1a9c0 to staging".into(),
                1 => other.zone = None,
                2 => other.actor = name("gg.addis.agent.eve"),
                3 => other.action = Action::Token { audience: "https://api.simien.dev".into(), scopes: vec!["deploy:*".into()] },
                4 => other.expires_at += 1,
                _ => other.class = "deploy.staging".into(),
            }
            others.push(other);
        }
        for other in others {
            assert_eq!(decide(&other, std::slice::from_ref(&approval), &devices, &rules(), NOW), Err(ApprovalError::BadProof), "{other:?}");
        }
        let mut renamed = ask.clone();
        renamed.id = "ap_other".into();
        assert_eq!(decide(&renamed, &[approval], &devices, &rules(), NOW), Err(ApprovalError::WrongRequest));
    }

    #[test]
    fn passkeys_must_be_for_this_site_this_challenge_and_a_verified_user() {
        let passkey_device = device("pk-1", "gg.addis.human.sami", DeviceKind::Passkey);
        let devices = [passkey_device.device.clone()];
        let ask = request("deploy.production");
        let ok = passkey(&passkey_device, &ask, Decision::Approve, "https://id.simien.dev", 0x05);
        assert_eq!(decide(&ask, &[ok], &devices, &rules(), NOW), Ok(Outcome::Approved));
        for (origin, flags, what) in [
            ("https://evil.example", 0x05, "another origin"),
            ("https://id.simien.dev", 0x01, "user not verified"),
            ("https://id.simien.dev", 0x04, "user not present"),
        ] {
            let approval = passkey(&passkey_device, &ask, Decision::Approve, origin, flags);
            assert_eq!(decide(&ask, &[approval], &devices, &rules(), NOW), Err(ApprovalError::BadProof), "{what}");
        }
        // A plain signature can't stand in for a passkey's assertion.
        let raw = signed(&passkey_device, &ask, Decision::Approve);
        assert_eq!(decide(&ask, &[raw], &devices, &rules(), NOW), Err(ApprovalError::BadProof));
    }

    #[test]
    fn the_highest_classes_need_two_of_the_approvers_devices() {
        let phone = device("phone-1", "gg.addis.human.sami", DeviceKind::Phone);
        let mac = device("mac-1", "gg.addis.human.sami", DeviceKind::Mac);
        let devices = [phone.device.clone(), mac.device.clone()];
        let ask = request("policy.widen");
        let once = signed(&phone, &ask, Decision::Approve);
        assert_eq!(decide(&ask, std::slice::from_ref(&once), &devices, &rules(), NOW), Ok(Outcome::Pending { have: 1, need: 2 }), "the rule says 1; the floor is 2");
        assert_eq!(decide(&ask, &[once.clone(), once.clone()], &devices, &rules(), NOW), Ok(Outcome::Pending { have: 1, need: 2 }), "one device twice is still one");
        assert_eq!(decide(&ask, &[once, signed(&mac, &ask, Decision::Approve)], &devices, &rules(), NOW), Ok(Outcome::Approved));
    }

    #[test]
    fn devices_must_be_enrolled_live_and_belong_to_an_allowed_human() {
        let phone = device("phone-1", "gg.addis.human.sami", DeviceKind::Phone);
        let stranger = device("phone-2", "gg.addis.human.eve", DeviceKind::Phone);
        let ask = request("policy.narrow");
        let mut revoked = phone.device.clone();
        revoked.revoked = true;
        assert_eq!(decide(&ask, &[signed(&phone, &ask, Decision::Approve)], &[], &rules(), NOW), Err(ApprovalError::UnknownDevice));
        assert_eq!(decide(&ask, &[signed(&phone, &ask, Decision::Approve)], &[revoked], &rules(), NOW), Err(ApprovalError::DeviceRevoked));
        // policy.* is sami's alone.
        assert_eq!(decide(&ask, &[signed(&stranger, &ask, Decision::Approve)], std::slice::from_ref(&stranger.device), &rules(), NOW), Err(ApprovalError::NotAnApprover));
        // A device whose key isn't the one enrolled.
        let impostor = device("phone-1", "gg.addis.human.sami", DeviceKind::Phone);
        assert_eq!(decide(&ask, &[signed(&impostor, &ask, Decision::Approve)], std::slice::from_ref(&phone.device), &rules(), NOW), Err(ApprovalError::BadProof));
        let mut late = ask.clone();
        late.expires_at = NOW;
        assert_eq!(decide(&late, &[], std::slice::from_ref(&phone.device), &rules(), NOW), Err(ApprovalError::Expired));
        assert_eq!(decide(&request("unknown.class"), &[], &[], &rules(), NOW), Err(ApprovalError::NoRule));
    }

    #[test]
    fn nobody_approves_their_own_request() {
        let phone = device("phone-1", "gg.addis.human.sami", DeviceKind::Phone);
        let mut ask = request("deploy.production");
        ask.actor = name("gg.addis.human.sami");
        ask.act_for = None;
        assert_eq!(decide(&ask, &[signed(&phone, &ask, Decision::Approve)], std::slice::from_ref(&phone.device), &rules(), NOW), Err(ApprovalError::OwnRequest));
    }

    #[test]
    fn delegated_approval_never_reaches_the_highest_classes_or_the_asker() {
        let orchestrator = name("gg.addis.agent.orchestrator");
        assert!(delegation_allowed(&request("deploy.staging"), &orchestrator));
        assert!(!delegation_allowed(&request("policy.widen"), &orchestrator));
        assert!(!delegation_allowed(&request("device.enroll"), &orchestrator));
        assert!(!delegation_allowed(&request("deploy.staging"), &name("gg.addis.agent.ava")), "the asker");
        assert!(!delegation_allowed(&request("deploy.staging"), &name("gg.addis.human.sami")), "humans approve with a device");
        let mut for_agent = request("deploy.staging");
        for_agent.act_for = Some(orchestrator.clone());
        assert!(!delegation_allowed(&for_agent, &orchestrator), "whom the asker acts for");
        assert!(!delegation_allowed(&request("deploy.staging"), &name("gg.addis.user.u-1")), "app users never approve");
    }
}
