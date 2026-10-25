//! Approver devices and approvals at a primary (architecture, section 6):
//! `harar device add|remove|recover`, `harar approvals`, `harar approve|deny
//! <id>`, `harar recovery-codes`.
//! On a Mac the device is a Secure Enclave key made for approving, apart from
//! the key `harar agent` unlocks with, that signs only after Touch ID (or the
//! login password). Its handle, useless on any other Mac, is kept with the
//! device id each primary gave it.
use crate::cli::{SocketArgs, print_json};
use anyhow::{Result, anyhow};
use clap::{Args, Subcommand};
use harar_client::VaultClient;
use harar_client::approvals::Decision;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct DeviceCmd {
    #[command(subcommand)]
    action: DeviceAction,
}

#[derive(Debug, Subcommand)]
enum DeviceAction {
    /// Enroll this Mac as one of your approver devices.
    Add(SocketArgs),
    /// Ask to revoke one of your devices: approved on one of your devices
    /// (never the last that can approve a widening).
    Remove {
        id: String,
        #[command(flatten)]
        socket: SocketArgs,
    },
    /// Enroll this Mac with one of your recovery codes, when you've lost
    /// your devices. It asks for the code (never an argument, so it stays out
    /// of shell history and `ps`); the Mac may deny at once, and approve after a day.
    Recover {
        /// Where the code comes from: a prompt that doesn't echo, by default.
        #[command(flatten)]
        code: crate::cli::secret_input::SecretInput,
        #[command(flatten)]
        socket: SocketArgs,
    },
}

/// Ask for a new set of your recovery codes; approving it on your device
/// shows them, and the old ones stop working.
#[derive(Debug, Args)]
pub struct RecoveryCodes {
    #[command(flatten)]
    socket: SocketArgs,
}

/// What waits for a person, and the approver devices.
#[derive(Debug, Args)]
pub struct Approvals {
    #[command(flatten)]
    socket: SocketArgs,
}

/// Approve a waiting request with this Mac's approver key.
#[derive(Debug, Args)]
pub struct Approve {
    id: String,
    #[command(flatten)]
    socket: SocketArgs,
}

/// Deny a waiting request with this Mac's approver key.
#[derive(Debug, Args)]
pub struct Deny {
    id: String,
    #[command(flatten)]
    socket: SocketArgs,
}

/// This Mac's approver key, and the device id each primary (by socket) gave it.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct ApproverFile {
    /// The Secure Enclave key's handle, base64.
    handle: String,
    devices: BTreeMap<String, String>,
}

fn approver_path() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"));
    if cfg!(target_os = "macos") { home.join("Library/Application Support/harar/approver.json") } else { home.join(".harar/approver.json") }
}

fn read_approver() -> Result<Option<ApproverFile>> {
    match std::fs::read_to_string(approver_path()) {
        Ok(text) => Ok(Some(serde_json::from_str(&text)?)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn write_approver(file: &ApproverFile) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = approver_path();
    std::fs::create_dir_all(path.parent().expect("a parent directory"))?;
    let part = path.with_extension("json.part");
    let mut out = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&part)?;
    out.write_all(serde_json::to_string_pretty(file)?.as_bytes())?;
    out.sync_all()?;
    std::fs::rename(part, path)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn key_for(socket: &std::path::Path) -> String {
    socket.to_string_lossy().into_owned()
}

pub async fn device(cmd: DeviceCmd) -> Result<()> {
    match cmd.action {
        DeviceAction::Add(socket) => add(socket.socket, None).await,
        // Empty input is refused here, never spent as one of the hour's tries.
        DeviceAction::Recover { code, socket } => add(socket.socket, Some(code.read("Recovery code")?)).await,
        DeviceAction::Remove { id, socket } => {
            // A request one of your devices approves; this Mac's own record of
            // its id goes once a later `harar device add` enrolls it again.
            let pending = VaultClient::from_socket_path(&socket.socket).remove_device(&id).await?;
            eprintln!("Approve it on one of your devices: harar approve {}", pending.request.id);
            print_json(&serde_json::json!({ "ok": true, "waiting": pending.request.id, "description": pending.description }))
        }
    }
}

/// The device `harar device add` sends for a 65-byte uncompressed P-256 key:
/// a Mac key that asks first. The primary sets its id, owner and times.
#[cfg(target_os = "macos")]
fn device_view(public: &[u8]) -> harar_client::approvals::ApproverDevice {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use harar_client::approvals::{ApproverDevice, DeviceKind};
    ApproverDevice {
        id: String::new(),
        human: "x.x.human.x".parse().expect("a stand-in name"),
        kind: DeviceKind::Mac,
        public_key: harar_client::Jwk {
            kty: "EC".into(),
            kid: String::new(),
            crv: "P-256".into(),
            alg: "ES256".into(),
            key_use: "sig".into(),
            x: URL_SAFE_NO_PAD.encode(&public[1..33]),
            y: Some(URL_SAFE_NO_PAD.encode(&public[33..65])),
        },
        credential_id: None,
        enrolled_at: 0,
        // Made with Presence::Required: it signs only after Touch ID or the password.
        user_verification: true,
        backup_eligible: false,
        sign_count: 0,
        reserved_after: 0,
        revoked: false,
    }
}

/// Enrolls this Mac's approver key: as another device, or with a recovery
/// code when `code` is given.
#[cfg(target_os = "macos")]
async fn add(socket: PathBuf, code: Option<String>) -> Result<()> {
    use crate::enclave::{EnclaveKey, Presence};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    // One approver key per Mac user, made once; it asks for Touch ID or the
    // login password every time it signs.
    let mut file = match read_approver()? {
        Some(file) => file,
        None => {
            // Kept before the primary is asked, so a refusal never leaves a
            // key behind that nothing knows: the next try uses it.
            let file = ApproverFile { handle: STANDARD.encode(EnclaveKey::create(Presence::Required)?.handle()?), devices: BTreeMap::new() };
            write_approver(&file)?;
            file
        }
    };
    let key = EnclaveKey::from_handle(&STANDARD.decode(&file.handle)?)?;
    let public = key.public_key()?;
    if public.len() != 65 || public[0] != 4 {
        return Err(anyhow!("the Secure Enclave key isn't an uncompressed P-256 key"));
    }
    let device = device_view(&public);
    // To compare with what an approver is shown before they approve this key.
    let fingerprint = harar_client::approvals::device_fingerprint(&device);
    let client = VaultClient::from_socket_path(&socket);
    if let Some(code) = code {
        let (id, others) = client.recover(&code, device).await?;
        file.devices.insert(key_for(&socket), id.clone());
        write_approver(&file)?;
        let others: Vec<_> = others.iter().map(|d| serde_json::json!({ "id": d.id, "fingerprint": harar_client::approvals::device_fingerprint(d) })).collect();
        eprintln!("This Mac can deny requests now and approve them after a day. Your other devices are told (harar approvals).");
        return print_json(&serde_json::json!({ "ok": true, "device": id, "fingerprint": fingerprint, "your_other_devices": others }));
    }
    let added = client.add_device(device).await?;
    let (enrolled, pending) = (added.id, added.pending);
    if let Some(codes) = &added.recovery_codes {
        show_codes(codes);
    }
    let id = match (&enrolled, &pending) {
        (Some(id), _) => id.clone(),
        (None, Some(pending)) => match &pending.waiting {
            harar_client::primary::Waiting::Device { device } => device.id.clone(),
            _ => return Err(anyhow!("the primary answered with an unexpected request")),
        },
        (None, None) => return Err(anyhow!("the primary enrolled nothing")),
    };
    file.devices.insert(key_for(&socket), id.clone());
    write_approver(&file)?;
    match pending {
        None => print_json(&serde_json::json!({ "ok": true, "device": id, "fingerprint": fingerprint })),
        Some(pending) => print_json(&serde_json::json!({
            "ok": true,
            "device": id,
            "fingerprint": fingerprint,
            "waiting": pending.request.id,
            "description": pending.description,
        })),
    }
}

/// Recovery codes go to the terminal, never to the JSON a script might log.
#[cfg(target_os = "macos")]
fn show_codes(codes: &[String]) {
    eprintln!("Your recovery codes. Each works once; keep them in a password manager or on paper. They won't be shown again.");
    for code in codes {
        eprintln!("  {code}");
    }
}

pub async fn recovery_codes(cmd: RecoveryCodes) -> Result<()> {
    let pending = VaultClient::from_socket_path(&cmd.socket.socket).new_recovery_codes().await?;
    eprintln!("Approve it on your device: harar approve {}", pending.request.id);
    print_json(&serde_json::json!({ "ok": true, "waiting": pending.request.id, "description": pending.description }))
}

#[cfg(not(target_os = "macos"))]
async fn add(_socket: PathBuf, _code: Option<String>) -> Result<()> {
    Err(anyhow!("an approver key needs a Mac's Secure Enclave for now; passkeys come with the approval page"))
}

pub async fn approvals(cmd: Approvals) -> Result<()> {
    let harar_client::Approvals { pending, devices, notices, recovery_codes_left } = VaultClient::from_socket_path(&cmd.socket.socket).approvals().await?;
    for notice in &notices {
        eprintln!("notice: {}", notice.text);
    }
    let waiting: Vec<_> = pending
        .iter()
        .map(|p| serde_json::json!({ "id": p.request.id, "class": p.request.class, "description": p.description, "expires_at": p.request.expires_at }))
        .collect();
    let devices: Vec<_> = devices
        .iter()
        .map(|d| {
            serde_json::json!({
                "id": d.id,
                "human": d.human.to_string(),
                "kind": d.kind,
                "fingerprint": harar_client::approvals::device_fingerprint(d),
                "revoked": d.revoked,
            })
        })
        .collect();
    let notices: Vec<_> = notices.iter().map(|n| serde_json::json!({ "at": n.at, "text": n.text })).collect();
    print_json(&serde_json::json!({
        "ok": true,
        "waiting": waiting,
        "devices": devices,
        "notices": notices,
        "recovery_codes_left": recovery_codes_left,
    }))
}

pub async fn approve(cmd: Approve) -> Result<()> {
    decide(cmd.id, cmd.socket.socket, Decision::Approve).await
}

pub async fn deny(cmd: Deny) -> Result<()> {
    decide(cmd.id, cmd.socket.socket, Decision::Deny).await
}

#[cfg(target_os = "macos")]
async fn decide(id: String, socket: PathBuf, decision: Decision) -> Result<()> {
    use crate::enclave::EnclaveKey;
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use harar_client::approvals::{Approval, Proof};
    let file = read_approver()?.ok_or_else(|| anyhow!("this Mac has no approver key yet: harar device add"))?;
    let device_id = file
        .devices
        .get(&key_for(&socket))
        .cloned()
        .ok_or_else(|| anyhow!("this Mac isn't an approver device at this primary yet: harar device add"))?;
    let client = VaultClient::from_socket_path(&socket);
    let pending = client.approvals().await?.pending;
    let waiting = pending.into_iter().find(|p| p.request.id == id).ok_or_else(|| anyhow!("no request {id} is waiting"))?;
    // What is shown must be what is signed: the request's detail is the hash
    // of exactly what it would do, so text from anywhere else can't be
    // passed off as this request.
    if waiting.request.detail.as_deref() != Some(harar_client::primary::waiting_detail(&waiting.waiting).as_str()) {
        return Err(anyhow!("request {id} doesn't match what it would do; not signing"));
    }
    // What the person is deciding, before Touch ID asks.
    eprintln!("{}", waiting.description);
    eprintln!("{}", serde_json::to_string_pretty(&waiting.waiting)?);
    let key = EnclaveKey::from_handle(&STANDARD.decode(&file.handle)?)?;
    let signature = key.sign(&waiting.request.challenge(decision, &device_id))?;
    let (result, codes) = client.submit(Approval { request_id: id, device_id, decision, proof: Proof::Signature { signature: URL_SAFE_NO_PAD.encode(signature) } }).await?;
    if let Some(codes) = &codes {
        show_codes(codes);
    }
    print_json(&serde_json::json!({ "ok": true, "decision": result }))
}

#[cfg(not(target_os = "macos"))]
async fn decide(_id: String, _socket: PathBuf, _decision: Decision) -> Result<()> {
    Err(anyhow!("approving needs a Mac's Secure Enclave for now; passkeys come with the approval page"))
}
