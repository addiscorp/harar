//! What the primary and the per-user agent share: who is on the other end of
//! a local socket, reading one request from it, and the encrypted key file.

use anyhow::{Context, Result, anyhow};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;

/// Requests larger than this are not read.
pub(crate) const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// Who is calling, as the kernel reports it. A caller can't choose any of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PeerCred {
    pub uid: u32,
    pub pid: i32,
    pub username: Option<String>,
}

pub(crate) fn peer_credentials(stream: &UnixStream) -> Result<PeerCred> {
    let (uid, pid) = peer_uid_pid(stream.as_raw_fd())?;
    Ok(PeerCred { uid, pid, username: username_for_uid(uid) })
}

#[cfg(target_os = "linux")]
fn peer_uid_pid(fd: std::os::fd::RawFd) -> Result<(u32, i32)> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid for writes and sized for SO_PEERCRED.
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut _ as *mut libc::c_void, &mut len) };
    if rc != 0 {
        return Err(anyhow!(std::io::Error::last_os_error()));
    }
    Ok((cred.uid, cred.pid))
}

#[cfg(target_os = "macos")]
fn peer_uid_pid(fd: std::os::fd::RawFd) -> Result<(u32, i32)> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `uid` and `gid` are valid out-pointers for getpeereid.
    if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
        return Err(anyhow!(std::io::Error::last_os_error()));
    }
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: `pid` and `len` are valid for writes and sized for LOCAL_PEERPID.
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_LOCAL, libc::LOCAL_PEERPID, &mut pid as *mut _ as *mut libc::c_void, &mut len) };
    if rc != 0 {
        return Err(anyhow!(std::io::Error::last_os_error()));
    }
    Ok((uid, pid))
}

/// Looks the account up through the system user database, so it also finds
/// macOS accounts, which are not listed in /etc/passwd.
pub(crate) fn username_for_uid(uid: u32) -> Option<String> {
    let mut buf = vec![0 as libc::c_char; 4096];
    // SAFETY: an all-zero passwd is a valid out-parameter for getpwuid_r.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid and `buf` outlives the call and the read of `pw_name`.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() || pwd.pw_name.is_null() {
        return None;
    }
    // SAFETY: on success `pw_name` points to a NUL-terminated string inside `buf`.
    let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) };
    Some(name.to_string_lossy().into_owned())
}

/// Whether `name` is a user on this machine, through the system user
/// database (so macOS accounts count too).
pub(crate) fn user_exists(name: &str) -> bool {
    let Ok(name) = std::ffi::CString::new(name) else { return false };
    let mut buf = vec![0 as libc::c_char; 4096];
    // SAFETY: an all-zero passwd is a valid out-parameter for getpwnam_r.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call.
    let rc = unsafe { libc::getpwnam_r(name.as_ptr(), &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    rc == 0 && !result.is_null()
}

/// Takes an exclusive lock on `path` (made 0600 if missing), or fails at once
/// if another process holds it. The lock lasts as long as the file is open.
pub(crate) fn lock_exclusive(path: &Path) -> Result<fs::File> {
    let file = OpenOptions::new().create(true).truncate(false).write(true).mode(0o600).open(path).with_context(|| format!("open {}", path.display()))?;
    // SAFETY: the descriptor is open for the whole call.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(anyhow!("{} is locked: {}", path.display(), std::io::Error::last_os_error()));
    }
    Ok(file)
}

/// Reads one JSON request. Clients don't always half-close the socket, so a
/// complete JSON value ends it too.
pub(crate) async fn read_request_bytes(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await.context("read request")?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if request.len() > MAX_REQUEST_BYTES || serde_json::from_slice::<serde_json::Value>(&request).is_ok() {
            break;
        }
    }
    Ok(request)
}

/// The encrypted key file: a JSON map, encrypted with age to the master key.
pub(crate) fn load_keys(path: &Path, identity: &age::x25519::Identity) -> Result<HashMap<String, String>> {
    match fs::read(path) {
        Ok(bytes) if bytes.is_empty() => Ok(HashMap::new()),
        Ok(bytes) => {
            let plaintext = zeroize::Zeroizing::new(
                age::decrypt(identity, &bytes)
                    .with_context(|| format!("decrypt {}; refusing to start on state that can't be read", path.display()))?,
            );
            serde_json::from_slice(&plaintext).with_context(|| format!("decode {}", path.display()))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
        Err(err) => Err(err).with_context(|| format!("read {}", path.display())),
    }
}

/// Encrypts `keys` to `recipient` and atomically replaces `path` (mode 0600).
pub(crate) fn write_encrypted_keys(path: &Path, recipient: &age::x25519::Recipient, keys: &HashMap<String, String>) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Err(anyhow!("the state path must have a parent folder"));
    };
    let plaintext = zeroize::Zeroizing::new(serde_json::to_vec(keys).context("encode the key file")?);
    let ciphertext = age::encrypt(recipient, &plaintext).context("encrypt the key file")?;
    let tmp_path = path.with_extension(format!("age.tmp.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&tmp_path)
        .with_context(|| format!("open {}", tmp_path.display()))?;
    file.write_all(&ciphertext).context("write the key file")?;
    file.sync_all().context("sync the key file")?;
    fs::rename(&tmp_path, path).with_context(|| format!("rename {} to {}", tmp_path.display(), path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).with_context(|| format!("chmod 0600 {}", path.display()))?;
    fs::File::open(parent).and_then(|dir| dir.sync_all()).with_context(|| format!("sync {}", parent.display()))?;
    Ok(())
}

pub(crate) fn now_epoch_seconds() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("the clock is after 1970").as_secs()
}
