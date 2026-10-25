//! Approver devices and approvals at a primary (architecture, section 6):
//! `harar device add|remove`, `harar approvals`, `harar approve|deny <id>`.
//! On a Mac the device is a Secure Enclave key made for approving, apart from
//! the key `harar agent` unlocks with, that signs only after Touch ID (or the
//! login password). Its handle, useless on any other Mac, is kept with the
//! device id each primary gave it.
use crate::cli::{SocketArgs, print_json};
use anyhow::{Result, anyhow};
use clap::{Args, Subcommand};
use harar_client::VaultClient;
use harar_client::approvals::{Approval, Decision, Proof};
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
    /// Revoke one of your devices (never the last that can approve a widening).
    Remove {
        id: String,
        #[command(flatten)]
        socket: SocketArgs,
    },
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
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/harar/approver.json")
    } else {
        home.join(".harar/approver.json")
    }
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
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&part)?;
    out.write_all(serde_json::to_string_pretty(file)?.as_bytes())?;
    out.sync_all()?;
    std::fs::rename(part, path)?;
    Ok(())
}

fn key_for(socket: &std::path::Path) -> String {
    socket.to_string_lossy().into_owned()
}

pub async fn device(cmd: DeviceCmd) -> Result<()> {
    match cmd.action {
        DeviceAction::Add(socket) => add(socket.socket).await,
        DeviceAction::Remove { id, socket } => {
            VaultClient::from_socket_path(&socket.socket)
                .remove_device(&id)
                .await?;
            if let Some(mut file) = read_approver()? {
                file.devices.retain(|_, enrolled| *enrolled != id);
                write_approver(&file)?;
            }
            print_json(&serde_json::json!({ "ok": true }))
        }
    }
}

#[cfg(target_os = "macos")]
async fn add(socket: PathBuf) -> Result<()> {
    use crate::enclave::{EnclaveKey, Presence};
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use harar_client::approvals::{ApproverDevice, DeviceKind};
    // One approver key per Mac user, made once; it asks for Touch ID or the
    // login password every time it signs.
    let mut file = match read_approver()? {
        Some(file) => file,
        None => ApproverFile {
            handle: STANDARD.encode(EnclaveKey::create(Presence::Required)?.handle()?),
            devices: BTreeMap::new(),
        },
    };
    let key = EnclaveKey::from_handle(&STANDARD.decode(&file.handle)?)?;
    let public = key.public_key()?;
    if public.len() != 65 || public[0] != 4 {
        return Err(anyhow!(
            "the Secure Enclave key isn't an uncompressed P-256 key"
        ));
    }
    let device = ApproverDevice {
        // The primary sets the id, the owner (the caller) and the times.
        id: String::new(),
        human: "x.x.human.x".parse()?,
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
    };
    let (enrolled, pending) = VaultClient::from_socket_path(&socket)
        .add_device(device)
        .await?;
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
        None => print_json(&serde_json::json!({ "ok": true, "device": id })),
        Some(pending) => print_json(&serde_json::json!({
            "ok": true,
            "device": id,
            "waiting": pending.request.id,
            "description": pending.description,
        })),
    }
}

#[cfg(not(target_os = "macos"))]
async fn add(_socket: PathBuf) -> Result<()> {
    Err(anyhow!(
        "an approver key needs a Mac's Secure Enclave for now; passkeys come with the approval page"
    ))
}

pub async fn approvals(cmd: Approvals) -> Result<()> {
    let (pending, devices) = VaultClient::from_socket_path(&cmd.socket.socket)
        .approvals()
        .await?;
    let waiting: Vec<_> = pending
        .iter()
        .map(|p| serde_json::json!({ "id": p.request.id, "class": p.request.class, "description": p.description, "expires_at": p.request.expires_at }))
        .collect();
    let devices: Vec<_> = devices
        .iter()
        .map(|d| serde_json::json!({ "id": d.id, "human": d.human.to_string(), "kind": d.kind, "revoked": d.revoked }))
        .collect();
    print_json(&serde_json::json!({ "ok": true, "waiting": waiting, "devices": devices }))
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
    let file = read_approver()?
        .ok_or_else(|| anyhow!("this Mac has no approver key yet: harar device add"))?;
    let device_id = file
        .devices
        .get(&key_for(&socket))
        .cloned()
        .ok_or_else(|| {
            anyhow!("this Mac isn't an approver device at this primary yet: harar device add")
        })?;
    let client = VaultClient::from_socket_path(&socket);
    let (pending, _) = client.approvals().await?;
    let waiting = pending
        .into_iter()
        .find(|p| p.request.id == id)
        .ok_or_else(|| anyhow!("no request {id} is waiting"))?;
    // What the person is deciding, before Touch ID asks.
    eprintln!("{}", waiting.description);
    let key = EnclaveKey::from_handle(&STANDARD.decode(&file.handle)?)?;
    let signature = key.sign(&waiting.request.challenge(decision, &device_id))?;
    let result = client
        .submit(Approval {
            request_id: id,
            device_id,
            decision,
            proof: Proof::Signature {
                signature: URL_SAFE_NO_PAD.encode(signature),
            },
        })
        .await?;
    print_json(&serde_json::json!({ "ok": true, "decision": result }))
}

#[cfg(not(target_os = "macos"))]
async fn decide(_id: String, _socket: PathBuf, _decision: Decision) -> Result<()> {
    Err(anyhow!(
        "approving needs a Mac's Secure Enclave for now; passkeys come with the approval page"
    ))
}
