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

fn run_in(dir: &Path, args: &[&str], socket: &Path) -> Output {
    harar()
        .current_dir(dir)
        .args(args)
        .env("HARAR_SOCKET", socket)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn run_resolves_references_and_masks_them_in_output() {
    let agent = start_agent();
    json(&run(&["put", "dev/app/db"], &agent.socket, Some("postgres://u:s3cret-pw@db\n")));
    let dir = agent.socket.parent().unwrap();
    fs::write(dir.join(".env"), "DATABASE_URL=harar://dev/app/db\nPLAIN=visible\n").unwrap();

    let masked = run_in(dir, &["run", "--env-file", ".env", "--", "sh", "-c", "echo url=$DATABASE_URL plain=$PLAIN; echo err=$DATABASE_URL >&2"], &agent.socket);
    assert!(masked.status.success());
    assert_eq!(String::from_utf8_lossy(&masked.stdout), "url=<concealed by harar> plain=visible\n");
    assert_eq!(String::from_utf8_lossy(&masked.stderr), "err=<concealed by harar>\n");

    let sees = run_in(dir, &["run", "--env-file", ".env", "--", "sh", "-c", "test \"$DATABASE_URL\" = 'postgres://u:s3cret-pw@db' && echo match"], &agent.socket);
    assert_eq!(String::from_utf8_lossy(&sees.stdout), "match\n", "the command gets the real value");

    let raw = run_in(dir, &["run", "--no-masking", "--env-file", ".env", "--", "sh", "-c", "echo $DATABASE_URL"], &agent.socket);
    assert_eq!(String::from_utf8_lossy(&raw.stdout), "postgres://u:s3cret-pw@db\n");
}

#[test]
fn run_passes_the_exit_code_through() {
    let agent = start_agent();
    json(&run(&["put", "dev/x"], &agent.socket, Some("v\n")));
    let dir = agent.socket.parent().unwrap();
    let out = run_in(dir, &["run", "--", "sh", "-c", "exit 7"], &agent.socket);
    assert_eq!(out.status.code(), Some(7));
}

#[test]
fn run_refuses_to_start_when_a_reference_is_missing() {
    let agent = start_agent();
    let dir = agent.socket.parent().unwrap();
    let marker = dir.join("started");
    fs::write(dir.join(".env"), "TOKEN=harar://dev/nope\n").unwrap();
    let out = run_in(dir, &["run", "--env-file", ".env", "--", "touch", marker.to_str().unwrap()], &agent.socket);

    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("TOKEN refers to harar://dev/nope"));
    assert!(!marker.exists(), "the command must not start");
}

#[test]
fn import_moves_values_into_the_vault_and_rewrites_the_file() {
    let agent = start_agent();
    let dir = agent.socket.parent().unwrap();
    let env = dir.join(".env");
    fs::write(&env, "# app settings\nAPI_KEY=sk_live_abc123\nexport REGION=\"us east\"\nALREADY=harar://dev/other\nEMPTY=\n").unwrap();
    fs::set_permissions(&env, fs::Permissions::from_mode(0o640)).unwrap();

    let out = json(&run_in(dir, &["import", ".env", "--prefix", "dev/site"], &agent.socket));
    assert_eq!(out["stored"], serde_json::json!(["dev/site/API_KEY", "dev/site/REGION"]));

    let text = fs::read_to_string(&env).unwrap();
    assert_eq!(text, "# app settings\nAPI_KEY=harar://dev/site/API_KEY\nexport REGION=harar://dev/site/REGION\nALREADY=harar://dev/other\nEMPTY=\n");
    assert!(!text.contains("sk_live_abc123"));
    assert_eq!(fs::metadata(&env).unwrap().permissions().mode() & 0o777, 0o640);
    assert_eq!(json(&run(&["get", "dev/site/REGION"], &agent.socket, None))["value"], "us east");
}

#[test]
fn import_leaves_the_file_alone_when_the_vault_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join(".env");
    fs::write(&env, "API_KEY=sk_live_abc123\n").unwrap();
    let out = run_in(dir.path(), &["import", ".env"], &dir.path().join("no-agent.sock"));

    assert!(!out.status.success());
    assert_eq!(fs::read_to_string(&env).unwrap(), "API_KEY=sk_live_abc123\n");
}

#[test]
fn inject_fills_a_template_into_a_private_file() {
    let agent = start_agent();
    json(&run(&["put", "dev/cf/token"], &agent.socket, Some("cf-token-xyz\n")));
    let dir = agent.socket.parent().unwrap();
    fs::write(dir.join("wrangler.tpl.toml"), "name = \"site\"\napi_token = \"{{ harar://dev/cf/token }}\"\n").unwrap();
    fs::write(dir.join("wrangler.toml"), "stale").unwrap();
    fs::set_permissions(dir.join("wrangler.toml"), fs::Permissions::from_mode(0o644)).unwrap();

    let out = run_in(dir, &["inject", "-i", "wrangler.tpl.toml", "-o", "wrangler.toml"], &agent.socket);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(fs::read_to_string(dir.join("wrangler.toml")).unwrap(), "name = \"site\"\napi_token = \"cf-token-xyz\"\n");
    assert_eq!(fs::metadata(dir.join("wrangler.toml")).unwrap().permissions().mode() & 0o777, 0o600);

    fs::write(dir.join("bad.tpl"), "x = \"{{ harar://dev/missing }}\"\n").unwrap();
    let bad = run_in(dir, &["inject", "-i", "bad.tpl", "-o", "bad.out"], &agent.socket);
    assert!(!bad.status.success());
    assert!(!dir.join("bad.out").exists(), "nothing is written when a reference is missing");
}
