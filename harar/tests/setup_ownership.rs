use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

#[test]
fn setup_refuses_attacker_owned_state_directory_and_signing_key() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping privileged distinct-UID setup fixture (requires root/CAP_CHOWN)");
        return;
    }

    let operator = unsafe { libc::geteuid() };
    let attacker = operator.checked_add(1).expect("a distinct attacker uid");
    let temp = tempfile::tempdir().expect("create test directory");

    let attacker_state_dir = temp.path().join("attacker-state");
    fs::create_dir(&attacker_state_dir).expect("create attacker state directory");
    set_owner(&attacker_state_dir, attacker);
    assert_setup_refused(
        &attacker_state_dir,
        &temp.path().join("attacker-state.log"),
        &temp.path().join("attacker-state.toml"),
        "state directory",
    );

    let state_dir = temp.path().join("state");
    fs::create_dir(&state_dir).expect("create state directory");
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700))
        .expect("secure state directory");
    let signing_key = state_dir.join("harar-signing.key");
    fs::write(&signing_key, [7_u8; 32]).expect("create signing key");
    fs::set_permissions(&signing_key, fs::Permissions::from_mode(0o600))
        .expect("secure signing key");
    set_owner(&signing_key, attacker);
    assert_setup_refused(
        &state_dir,
        &temp.path().join("signing-key.log"),
        &temp.path().join("signing-key.toml"),
        "signing key",
    );
}

fn assert_setup_refused(state_dir: &Path, log_dir: &Path, config_path: &Path, kind: &str) {
    let output = Command::new(env!("CARGO_BIN_EXE_harar"))
        .args([
            "setup",
            "--yes",
            "--state-dir",
            state_dir.to_str().expect("UTF-8 state path"),
            "--log-dir",
            log_dir.to_str().expect("UTF-8 log path"),
            "--config-path",
            config_path.to_str().expect("UTF-8 config path"),
        ])
        .output()
        .expect("run harar setup");
    assert!(
        !output.status.success(),
        "setup accepted attacker-owned {kind}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(&format!("refusing {kind}")),
        "setup did not report refusing attacker-owned {kind}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn set_owner(path: &Path, uid: u32) {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("NUL-free path");
    assert_eq!(
        unsafe { libc::chown(path.as_ptr(), uid, uid) },
        0,
        "chown fixture to attacker uid"
    );
}
