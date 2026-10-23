//! Starts a real `harar agent` and drives it with the CLI, as a person would.
//! Uses a file-tier master key so nothing can prompt.

use age::secrecy::ExposeSecret;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

struct Agent {
    child: Child,
    socket: PathBuf,
    state: PathBuf,
    _dir: tempfile::TempDir,
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn harar() -> Command {
    Command::new(env!("CARGO_BIN_EXE_harar"))
}

fn start_agent() -> Agent {
    let dir = tempfile::Builder::new().prefix("ha").tempdir().unwrap();
    let key = dir.path().join("master.key");
    fs::write(&key, age::x25519::Identity::generate().to_string().expose_secret()).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o400)).unwrap();
    let socket = dir.path().join("agent.sock");
    let state = dir.path().join("vault.age");
    let child = harar()
        .args(["agent", "--socket"])
        .arg(&socket)
        .arg("--state")
        .arg(&state)
        .arg("--key")
        .arg(&key)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn harar agent");
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::os::unix::net::UnixStream::connect(&socket).is_err() {
        assert!(Instant::now() < deadline, "agent did not listen on {}", socket.display());
        std::thread::sleep(Duration::from_millis(25));
    }
    Agent { child, socket, state, _dir: dir }
}

fn run(args: &[&str], socket: &Path, stdin: Option<&str>) -> Output {
    let mut child = harar()
        .args(args)
        .arg("--socket")
        .arg(socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = stdin {
        child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    }
    drop(child.stdin.take());
    child.wait_with_output().unwrap()
}

fn json(output: &Output) -> serde_json::Value {
    assert!(output.status.success(), "harar failed: {}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn secrets_round_trip_through_the_agent_and_stay_encrypted() {
    let agent = start_agent();
    assert_eq!(json(&run(&["status"], &agent.socket, None))["unlocked"], false);

    json(&run(&["put", "dev/neon/url", "--secret-stdin"], &agent.socket, Some("postgres://user:hunter2-very-secret@db\n")));
    assert_eq!(json(&run(&["status"], &agent.socket, None))["unlocked"], true);
    let got = json(&run(&["get", "dev/neon/url"], &agent.socket, None));
    assert_eq!(got["value"], "postgres://user:hunter2-very-secret@db");

    let on_disk = fs::read(&agent.state).unwrap();
    assert!(!on_disk.windows(20).any(|w| w == b"hunter2-very-secret@"));

    json(&run(&["lock"], &agent.socket, None));
    assert_eq!(json(&run(&["status"], &agent.socket, None))["unlocked"], false);
    let again = json(&run(&["get", "dev/neon/url"], &agent.socket, None));
    assert_eq!(again["value"], "postgres://user:hunter2-very-secret@db", "unlocks again from disk");
}

#[test]
fn a_second_agent_on_the_same_socket_is_refused() {
    let agent = start_agent();
    let output = harar()
        .args(["agent", "--socket"])
        .arg(&agent.socket)
        .arg("--key")
        .arg(agent.socket.with_file_name("master.key"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already listening"));
}

#[test]
fn agent_refuses_to_start_without_a_master_key() {
    let dir = tempfile::tempdir().unwrap();
    let output = harar()
        .args(["agent", "--socket"])
        .arg(dir.path().join("a.sock"))
        .arg("--key")
        .arg(dir.path().join("missing.key"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("harar key init"));
}
