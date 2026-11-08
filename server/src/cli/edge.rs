//! `harar edge`: write an edge for Cloudflare, Vercel or Supabase, pair this
//! machine with it, and manage what it serves (docs/edge.md).
//!
//! This machine becomes a device of the edge: a P-256 key (the Secure Enclave
//! on a Mac, a 0600 key file otherwise or with --file-key) that signs every
//! request. Which edges it is paired with lives in `edges.json` (state_dir:
//! Application Support on a Mac, ~/.local/state/harar on Linux).

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use clap::{ArgGroup, Args, Subcommand};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{IsTerminal, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::print_json;
use super::secret_input::SecretInput;

mod files {
    include!(concat!(env!("OUT_DIR"), "/edge_files.rs"));
}

/// The edge key, for the platform's secret store.
const KEY_FILE: &str = ".harar-edge.key";
/// The edge key as KEY=VALUE, for `supabase secrets set --env-file`.
const ENV_FILE: &str = ".harar-edge.env";
/// The setup code, until `harar edge pair --dir` uses it and removes it.
const SETUP_FILE: &str = ".harar-edge.setup";
/// The edge key encrypted with the recovery code (age, scrypt), until
/// `harar edge pair --dir` stores it on the edge and removes it.
const RECOVERY_FILE: &str = ".harar-edge.recovery";
/// Characters in the recovery code: 28 Crockford characters, 140 bits.
const RECOVERY_CODE_LEN: usize = 28;

#[derive(Debug, Args)]
pub struct Edge {
    #[command(subcommand)]
    command: EdgeCmd,
}

#[derive(Debug, Subcommand)]
enum EdgeCmd {
    /// Write an edge for Cloudflare, Vercel or Supabase into a folder.
    Init(Init),
    /// Pair this machine with an edge, as one of its devices.
    Pair(Pair),
    /// Make a one-time code (10 minutes) another device pairs with.
    Pairing(Target),
    /// The devices paired with the edge.
    Devices(Target),
    /// Unpair a device. Immediate; the last device can't be unpaired.
    Unpair(Unpair),
    /// The secrets the edge holds: paths and versions, never values.
    Secrets(Target),
    /// Put a secret on the edge, for service tokens to resolve.
    Put(Put),
    /// Delete a secret from the edge.
    Delete(Delete),
    /// Service tokens: create, list, revoke.
    #[command(subcommand)]
    Token(TokenCmd),
    /// The edge's log, with its hash chain checked.
    Log(Log),
    /// Restore the edge key if the platform lost it: from this Mac's sealed
    /// copy (Touch ID), or with --with-code from the recovery code and the
    /// copy on the edge. Pipe it to the platform:
    /// harar edge recover | npx wrangler secret put HARAR_EDGE_KEY
    Recover(Recover),
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("platform").required(true).args(["cloudflare", "vercel", "supabase"])))]
struct Init {
    /// Cloudflare Workers, with D1.
    #[arg(long)]
    cloudflare: bool,
    /// Vercel Functions, with any Postgres.
    #[arg(long)]
    vercel: bool,
    /// Supabase Edge Functions, with the project's Postgres.
    #[arg(long)]
    supabase: bool,
    /// The folder to write into (asked for when not given; ./harar-edge by default).
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Where the log goes: an OTLP/HTTP endpoint, best in another account.
    /// Asked for when not given; empty for none.
    #[arg(long)]
    log_sink: Option<String>,
}

#[derive(Debug, Args)]
struct Pair {
    /// The edge's URL (https://harar-edge.<you>.workers.dev, …).
    url: String,
    /// What the edge calls this device (default: this machine's name).
    #[arg(long)]
    name: Option<String>,
    /// The folder `harar edge init` wrote: its setup code is used, then removed.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Keep the device key in a 0600 file instead of the Secure Enclave.
    #[arg(long)]
    file_key: bool,
    /// The pairing code, when not taken from --dir: never an argument.
    #[command(flatten)]
    code: SecretInput,
}

#[derive(Debug, Args)]
struct Target {
    /// Which paired edge, by URL (needed only when there is more than one).
    #[arg(long)]
    edge: Option<String>,
}

#[derive(Debug, Args)]
struct Unpair {
    /// The device id (d-…), from `harar edge devices`.
    device: String,
    #[command(flatten)]
    target: Target,
}

#[derive(Debug, Args)]
struct Put {
    /// The secret's path (prod/shop/STRIPE_KEY).
    path: String,
    /// Record it as a rotation of the value before.
    #[arg(long)]
    rotate: bool,
    #[command(flatten)]
    value: SecretInput,
    #[command(flatten)]
    target: Target,
}

#[derive(Debug, Args)]
struct Delete {
    path: String,
    #[command(flatten)]
    target: Target,
}

#[derive(Debug, Subcommand)]
enum TokenCmd {
    /// Make a service token. It is shown once; the edge keeps only its hash.
    Create(TokenCreate),
    /// The edge's service tokens, never their secrets.
    List(Target),
    /// Revoke a token. Immediate.
    Revoke(TokenRevoke),
}

#[derive(Debug, Args)]
struct TokenCreate {
    /// What the token is for (railway-shop).
    name: String,
    /// Paths it may resolve: a path, or a prefix ending in * (prod/shop/*). Repeatable.
    #[arg(long = "read")]
    read: Vec<String>,
    /// Paths it may write. Repeatable.
    #[arg(long = "write")]
    write: Vec<String>,
    /// Seconds until it expires (default: never).
    #[arg(long)]
    expires_in: Option<u64>,
    #[command(flatten)]
    target: Target,
}

#[derive(Debug, Args)]
struct TokenRevoke {
    /// The token's id, from `harar edge token list`.
    id: String,
    #[command(flatten)]
    target: Target,
}

#[derive(Debug, Args)]
struct Log {
    /// Only rows after this sequence number.
    #[arg(long, default_value_t = 0)]
    after: u64,
    #[command(flatten)]
    target: Target,
}

pub async fn run(cmd: Edge) -> Result<()> {
    // The HTTP client blocks, and a Secure Enclave signature may wait for
    // Touch ID: both off the async runtime.
    tokio::task::spawn_blocking(move || run_blocking(cmd)).await?
}

fn run_blocking(cmd: Edge) -> Result<()> {
    match cmd.command {
        EdgeCmd::Init(cmd) => init(cmd),
        EdgeCmd::Pair(cmd) => pair(cmd),
        EdgeCmd::Pairing(t) => print_json(&Paired::find(&t)?.call("POST", "/v1/pairings", None)?),
        EdgeCmd::Devices(t) => print_json(&Paired::find(&t)?.call("GET", "/v1/devices", None)?),
        EdgeCmd::Unpair(cmd) => print_json(&Paired::find(&cmd.target)?.call("DELETE", &format!("/v1/devices/{}", cmd.device), None)?),
        EdgeCmd::Secrets(t) => print_json(&Paired::find(&t)?.call("GET", "/v1/secrets", None)?),
        EdgeCmd::Put(cmd) => {
            let edge = Paired::find(&cmd.target)?;
            let value = zeroize::Zeroizing::new(cmd.value.read_confirmed("Secret value")?);
            print_json(&edge.call("PUT", &secret_path(&cmd.path)?, Some(&json!({ "value": *value, "rotate": cmd.rotate })))?)
        }
        EdgeCmd::Delete(cmd) => print_json(&Paired::find(&cmd.target)?.call("DELETE", &secret_path(&cmd.path)?, None)?),
        EdgeCmd::Token(TokenCmd::Create(cmd)) => {
            let mut body = json!({ "name": cmd.name, "read": cmd.read, "write": cmd.write });
            if let Some(seconds) = cmd.expires_in {
                body["expires_in"] = json!(seconds);
            }
            let mut made = Paired::find(&cmd.target)?.call("POST", "/v1/tokens", Some(&body))?;
            made["note"] = json!("The token is shown this once; the edge keeps only its hash. Put it in the service's secrets.");
            print_json(&made)
        }
        EdgeCmd::Token(TokenCmd::List(t)) => print_json(&Paired::find(&t)?.call("GET", "/v1/tokens", None)?),
        EdgeCmd::Token(TokenCmd::Revoke(cmd)) => print_json(&Paired::find(&cmd.target)?.call("DELETE", &format!("/v1/tokens/{}", cmd.id), None)?),
        EdgeCmd::Log(cmd) => log(cmd),
        EdgeCmd::Recover(cmd) => recover(cmd),
    }
}

// ------------------------------------------------------------------ init

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Platform {
    Cloudflare,
    Vercel,
    Supabase,
}

impl Platform {
    fn name(self) -> &'static str {
        match self {
            Platform::Cloudflare => "cloudflare",
            Platform::Vercel => "vercel",
            Platform::Supabase => "supabase",
        }
    }
}

/// What `init` writes: each file's path in the folder and its contents.
fn edge_files(platform: Platform, fill: &[(&str, &str)]) -> Result<Vec<(String, String)>> {
    let layout: Value = serde_json::from_str(files::LAYOUT).context("edge/platforms/layout.json")?;
    let core = layout[platform.name()]["core"].as_str().ok_or_else(|| anyhow!("layout.json names no core file for {}", platform.name()))?;
    let mut out = vec![(core.to_owned(), files::CORE.to_owned())];
    for (p, path, text) in files::PLATFORM_FILES {
        if *p == platform.name() {
            let mut text = (*text).to_owned();
            for (name, value) in fill {
                text = text.replace(&format!("__{name}__"), value);
            }
            out.push(((*path).to_owned(), text));
        }
    }
    Ok(out)
}

fn init(cmd: Init) -> Result<()> {
    let platform = if cmd.cloudflare {
        Platform::Cloudflare
    } else if cmd.vercel {
        Platform::Vercel
    } else {
        Platform::Supabase
    };
    let dir = match cmd.dir {
        Some(dir) => dir,
        None => PathBuf::from(ask("Folder for the edge", "./harar-edge")?),
    };
    let sink = match cmd.log_sink {
        Some(sink) => sink,
        None => ask("Log sink: an OTLP/HTTP URL, best in another account (empty for none)", "")?,
    };
    if !sink.is_empty() {
        check_url(&sink).context("the log sink")?;
    }

    let mut code = [0u8; 16];
    OsRng.fill_bytes(&mut code);
    let code = URL_SAFE_NO_PAD.encode(code);
    let mut raw_key = zeroize::Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *raw_key);
    let key = zeroize::Zeroizing::new(STANDARD.encode(*raw_key));
    // The key's paper backup: a code shown once, and the key encrypted with
    // it, which `pair` stores on the edge. Each alone opens nothing.
    let recovery_code = harar::recovery::new_code(RECOVERY_CODE_LEN);
    let recovery_copy = seal_with_code(&recovery_code, &*raw_key)?;
    let hash = hex(&Sha256::digest(code.as_bytes()));
    let files = edge_files(platform, &[("HARAR_SETUP_CODE_HASH", &hash), ("HARAR_LOG_SINK", &sink)])?;

    // Supabase projects already have supabase/config.toml: add the
    // function's section to it rather than replace it.
    let mut writes = Vec::new();
    let mut appends = Vec::new();
    for (path, text) in files {
        let target = dir.join(&path);
        if platform == Platform::Supabase && path == "supabase/config.toml" && target.exists() {
            let current = fs::read_to_string(&target).with_context(|| format!("read {}", target.display()))?;
            if !current.contains("[functions.harar-edge]") {
                let section = text.lines().filter(|l| !l.starts_with('#')).collect::<Vec<_>>().join("\n");
                appends.push((target, format!("\n{}\n", section.trim())));
            }
            continue;
        }
        writes.push((target, text));
    }
    let secrets = [
        (dir.join(KEY_FILE), key.to_string()),
        (dir.join(SETUP_FILE), code.clone()),
        (dir.join(RECOVERY_FILE), recovery_copy),
    ];
    let env = (platform == Platform::Supabase).then(|| (dir.join(ENV_FILE), format!("HARAR_EDGE_KEY={}\n", *key)));
    let existing: Vec<_> = writes
        .iter()
        .map(|(p, _)| p)
        .chain(secrets.iter().map(|(p, _)| p))
        .chain(env.iter().map(|(p, _)| p))
        .filter(|p| p.exists())
        .map(|p| p.display().to_string())
        .collect();
    if !existing.is_empty() {
        bail!("{} already has {}; init writes a new edge and never replaces files", dir.display(), existing.join(", "));
    }

    let mut written = Vec::new();
    for (path, text) in &writes {
        fs::create_dir_all(path.parent().unwrap_or(&dir)).with_context(|| format!("create {}", dir.display()))?;
        fs::write(path, text).with_context(|| format!("write {}", path.display()))?;
        written.push(path.display().to_string());
    }
    for (path, section) in &appends {
        OpenOptions::new().append(true).open(path)?.write_all(section.as_bytes())?;
        written.push(format!("{} (added [functions.harar-edge])", path.display()));
    }
    for (path, text) in secrets.iter().chain(env.iter()) {
        write_private(path, text)?;
    }
    ignore(&dir.join(".gitignore"), &[KEY_FILE, ENV_FILE, SETUP_FILE, RECOVERY_FILE, ".dev.vars"])?;

    let d = dir.display();
    let next: Vec<String> = match platform {
        Platform::Cloudflare => vec![
            format!("cd {d}"),
            "npx wrangler deploy   # the first deploy also creates the D1 database".into(),
            format!("npx wrangler secret put HARAR_EDGE_KEY < {KEY_FILE}"),
            format!("harar edge pair https://harar-edge.<your-subdomain>.workers.dev --dir {d}"),
        ],
        Platform::Vercel => vec![
            format!("cd {d} && npx vercel link"),
            "Give the project a Postgres (Vercel's marketplace, Neon or Supabase) as DATABASE_URL".into(),
            format!("npx vercel env add HARAR_EDGE_KEY production < {KEY_FILE}"),
            "npx vercel deploy --prod".into(),
            format!("harar edge pair https://<your-project>.vercel.app --dir {d}"),
        ],
        Platform::Supabase => vec![
            format!("cd {d}"),
            format!("supabase secrets set --env-file {ENV_FILE}"),
            "supabase functions deploy harar-edge --no-verify-jwt".into(),
            format!("harar edge pair https://<project-ref>.supabase.co/functions/v1/harar-edge --dir {d}"),
        ],
    };
    print_json(&json!({
        "ok": true,
        "platform": platform.name(),
        "dir": dir,
        "written": written,
        "secrets": {
            "edge_key": dir.join(KEY_FILE),
            "setup_code": dir.join(SETUP_FILE),
        },
        "log_sink": if sink.is_empty() { Value::Null } else { json!(sink) },
        "recovery_code": recovery_code,
        "next": next,
        "note": "Write the recovery code down now: it is shown this once. With it, the edge key can be restored if the platform loses it (harar edge recover --with-code). The edge key, setup code and recovery copy are in 0600 files, ignored by git; `harar edge pair --dir` checks the edge has the key, keeps a copy sealed to this Mac's Secure Enclave, stores the recovery copy on the edge, and removes all three.",
    }))
}

/// A plain (echoed) question, for things that aren't secret.
fn ask(question: &str, default: &str) -> Result<String> {
    if !std::io::stdin().is_terminal() {
        return Ok(default.to_owned());
    }
    if default.is_empty() {
        eprint!("{question}: ");
    } else {
        eprint!("{question} [{default}]: ");
    }
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let line = line.trim();
    Ok(if line.is_empty() { default.to_owned() } else { line.to_owned() })
}

fn write_private(path: &Path, text: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

/// Adds the lines .gitignore doesn't have yet.
fn ignore(path: &Path, lines: &[&str]) -> Result<()> {
    let current = fs::read_to_string(path).unwrap_or_default();
    let missing: Vec<_> = lines.iter().filter(|l| !current.lines().any(|c| c.trim() == **l)).collect();
    if missing.is_empty() {
        return Ok(());
    }
    let mut text = String::new();
    if !current.is_empty() && !current.ends_with('\n') {
        text.push('\n');
    }
    for line in missing {
        text.push_str(line);
        text.push('\n');
    }
    OpenOptions::new().create(true).append(true).open(path)?.write_all(text.as_bytes())?;
    Ok(())
}

/// https://, or http:// to this machine only (a local edge or sink).
fn check_url(url: &str) -> Result<()> {
    let local = ["http://127.0.0.1", "http://localhost", "http://[::1]"];
    if url.starts_with("https://") || local.iter().any(|p| url.starts_with(p) && url[p.len()..].chars().next().is_none_or(|c| c == ':' || c == '/')) {
        Ok(())
    } else {
        bail!("{url:?} is not an https:// URL")
    }
}

// ------------------------------------------------------------------ devices

/// This machine's key for one edge.
enum DeviceKey {
    #[cfg(target_os = "macos")]
    Enclave(crate::enclave::EnclaveKey),
    File(SigningKey),
}

impl DeviceKey {
    /// The raw P-256 point (65 bytes), as the edge stores it.
    fn public_key(&self) -> Result<Vec<u8>> {
        match self {
            #[cfg(target_os = "macos")]
            DeviceKey::Enclave(key) => key.public_key(),
            DeviceKey::File(key) => Ok(VerifyingKey::from(key).to_encoded_point(false).as_bytes().to_vec()),
        }
    }

    /// ECDSA P-256 over SHA-256, raw r || s.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        let signature: Signature = match self {
            #[cfg(target_os = "macos")]
            DeviceKey::Enclave(key) => Signature::from_der(&key.sign(message)?).context("the Secure Enclave's signature")?,
            DeviceKey::File(key) => key.sign(message),
        };
        Ok(signature.to_bytes().into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "tier", rename_all = "kebab-case")]
enum StoredKey {
    /// The enclave's handle for the key: only this Mac's enclave can use it.
    SecureEnclave { handle: String },
    /// A 0600 file holding the private scalar.
    File { path: PathBuf },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Paired {
    url: String,
    device: String,
    name: String,
    key: StoredKey,
    /// The edge key, sealed to this Mac's Secure Enclave (base64), when
    /// this machine paired with the folder init wrote. Only this Mac can
    /// open it, with Touch ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    edge_key: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct EdgesFile {
    edges: Vec<Paired>,
}

/// Where this machine keeps its edges and their device keys: state that must
/// outlive a reboot. The agent's folder on macOS (Application Support); on
/// Linux `~/.local/state/harar`, never the agent's `$XDG_RUNTIME_DIR`, which
/// is emptied at logout.
fn state_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        return harar::agent_dir();
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"));
    home.join(".local/state/harar")
}

fn edges_path() -> PathBuf {
    state_dir().join("edges.json")
}

fn read_edges() -> Result<EdgesFile> {
    match fs::read_to_string(edges_path()) {
        Ok(text) => serde_json::from_str(&text).with_context(|| format!("read {}", edges_path().display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(EdgesFile::default()),
        Err(err) => Err(err).with_context(|| format!("read {}", edges_path().display())),
    }
}

fn write_edges(file: &EdgesFile) -> Result<()> {
    let path = edges_path();
    fs::create_dir_all(path.parent().expect("a parent folder"))?;
    let part = path.with_extension("json.part");
    let mut out = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&part)?;
    out.write_all(serde_json::to_string_pretty(file)?.as_bytes())?;
    out.sync_all()?;
    fs::rename(&part, &path)?;
    Ok(())
}

fn pair(cmd: Pair) -> Result<()> {
    let url = cmd.url.trim_end_matches('/').to_owned();
    check_url(&url).context("the edge")?;
    let mut edges = read_edges()?;
    if edges.edges.iter().any(|e| e.url == url) {
        bail!("this machine is already paired with {url}");
    }
    let setup = cmd.dir.as_ref().map(|d| d.join(SETUP_FILE)).filter(|p| p.exists());
    // With init's folder, the edge must already have init's key: only then
    // can the plaintext copy here be removed.
    let init_key = match cmd.dir.as_ref().map(|d| d.join(KEY_FILE)).filter(|p| p.exists()) {
        Some(path) => {
            let raw = read_key_file(&path)?;
            match edge_key_status(&url)? {
                Some(id) if id == key_id(&raw) => {}
                Some(_) => bail!("{url} has a different edge key than {}; set it with the platform (npx wrangler secret put HARAR_EDGE_KEY < {KEY_FILE}) and pair again", path.display()),
                None => bail!("{url} has no edge key yet; set it with the platform first (npx wrangler secret put HARAR_EDGE_KEY < {KEY_FILE}), then pair"),
            }
            Some((path, raw))
        }
        None => None,
    };
    let code = zeroize::Zeroizing::new(match &setup {
        Some(path) => fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?.trim().to_owned(),
        None => cmd.code.read("Pairing code")?,
    });
    let name = match cmd.name {
        Some(name) => name,
        None => hostname(),
    };

    let (key, stored) = new_key(&url, cmd.file_key)?;
    let public_key = URL_SAFE_NO_PAD.encode(key.public_key()?);
    let answer = send(&url, "POST", "/v1/pair", Some(&json!({ "code": *code, "name": name, "public_key": public_key })), None);
    let answer = match answer {
        Ok(answer) => answer,
        Err(err) => {
            if let StoredKey::File { path } = &stored {
                let _ = fs::remove_file(path);
            }
            return Err(err);
        }
    };
    let device = answer["device"].as_str().ok_or_else(|| anyhow!("{url} paired, but named no device"))?.to_owned();
    let edge_key = match (&init_key, &key) {
        #[cfg(target_os = "macos")]
        (Some((_, raw)), DeviceKey::Enclave(enclave)) => Some(STANDARD.encode(enclave.seal(&raw[..])?)),
        _ => None,
    };
    let paired = Paired { url: url.clone(), device: device.clone(), name: name.clone(), key: stored.clone(), edge_key: edge_key.clone() };
    edges.edges.push(paired.clone());
    write_edges(&edges)?;

    let mut removed = Vec::new();
    if let Some(dir) = &cmd.dir {
        let recovery = dir.join(RECOVERY_FILE);
        if recovery.exists() {
            let sealed = fs::read_to_string(&recovery).with_context(|| format!("read {}", recovery.display()))?;
            paired.call("PUT", "/v1/recovery", Some(&json!({ "sealed": sealed.trim() })))?;
            fs::remove_file(&recovery)?;
            removed.push(recovery.display().to_string());
        }
    }
    if let Some((path, _)) = &init_key {
        for file in [path.clone(), path.with_file_name(ENV_FILE)] {
            if file.exists() {
                fs::remove_file(&file).with_context(|| format!("remove {}", file.display()))?;
                removed.push(file.display().to_string());
            }
        }
    }
    if let Some(path) = setup {
        fs::remove_file(&path).with_context(|| format!("remove the used setup code {}", path.display()))?;
        removed.push(path.display().to_string());
    }
    print_json(&json!({
        "ok": true,
        "edge": url,
        "device": device,
        "name": name,
        "key": match stored { StoredKey::SecureEnclave { .. } => "secure-enclave", StoredKey::File { .. } => "file" },
        "edge_key_backup": match (&init_key, &edge_key) {
            (None, _) => "none here (this machine didn't run init)",
            (Some(_), Some(_)) => "sealed to this Mac's Secure Enclave, and the recovery code",
            (Some(_), None) => "the recovery code",
        },
        "removed": removed,
    }))
}

fn new_key(url: &str, file_key: bool) -> Result<(DeviceKey, StoredKey)> {
    #[cfg(target_os = "macos")]
    if !file_key && crate::enclave::available() {
        let key = crate::enclave::EnclaveKey::create(crate::enclave::Presence::Required)?;
        let handle = STANDARD.encode(key.handle()?);
        return Ok((DeviceKey::Enclave(key), StoredKey::SecureEnclave { handle }));
    }
    let _ = file_key;
    let key = SigningKey::random(&mut OsRng);
    let path = state_dir().join("edge-keys").join(format!("{}.p256", &hex(&Sha256::digest(url.as_bytes()))[..16]));
    let secret = zeroize::Zeroizing::new(STANDARD.encode(key.to_bytes()));
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("replace the unused key {}", path.display()))?;
    }
    write_private(&path, &secret)?;
    Ok((DeviceKey::File(key), StoredKey::File { path }))
}

impl Paired {
    /// The edge `--edge` names, or the only one this machine is paired with.
    fn find(target: &Target) -> Result<Paired> {
        let edges = read_edges()?.edges;
        match &target.edge {
            Some(url) => {
                let url = url.trim_end_matches('/');
                edges.into_iter().find(|e| e.url == url).ok_or_else(|| anyhow!("this machine is not paired with {url}; run harar edge pair {url}"))
            }
            None => match edges.len() {
                0 => bail!("this machine is not paired with an edge; run harar edge init, then harar edge pair"),
                1 => Ok(edges.into_iter().next().expect("one")),
                _ => bail!("this machine is paired with {} edges; say which with --edge <url>", edges.len()),
            },
        }
    }

    fn key(&self) -> Result<DeviceKey> {
        match &self.key {
            #[cfg(target_os = "macos")]
            StoredKey::SecureEnclave { handle } => Ok(DeviceKey::Enclave(crate::enclave::EnclaveKey::from_handle(&STANDARD.decode(handle)?)?)),
            #[cfg(not(target_os = "macos"))]
            StoredKey::SecureEnclave { .. } => bail!("this edge's device key is in a Mac's Secure Enclave"),
            StoredKey::File { path } => {
                let text = zeroize::Zeroizing::new(fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?);
                let bytes = zeroize::Zeroizing::new(STANDARD.decode(text.trim())?);
                Ok(DeviceKey::File(SigningKey::from_slice(&bytes).context("the device key file")?))
            }
        }
    }

    /// A signed request to this edge (docs/edge.md §3).
    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        send(&self.url, method, path, body, Some((&self.device, &self.key()?)))
    }
}

/// One request to an edge: signed by `device` when given. `path` is the API
/// path (/v1/…), which is what is signed, whatever the edge is mounted under.
fn send(url: &str, method: &str, path: &str, body: Option<&Value>, device: Option<(&str, &DeviceKey)>) -> Result<Value> {
    let body = body.map(serde_json::to_vec).transpose()?.unwrap_or_default();
    let mut headers = vec![("content-type".to_owned(), "application/json".to_owned())];
    if let Some((id, key)) = device {
        let time = crate::common::now_epoch_seconds().to_string();
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let nonce = URL_SAFE_NO_PAD.encode(nonce);
        let signed = ["harar-edge-v1", method, path, &time, &nonce, &hex(&Sha256::digest(&body))].join("\n");
        let signature = URL_SAFE_NO_PAD.encode(key.sign(signed.as_bytes())?);
        headers.extend([
            ("harar-device".to_owned(), id.to_owned()),
            ("harar-time".to_owned(), time),
            ("harar-nonce".to_owned(), nonce),
            ("harar-signature".to_owned(), signature),
        ]);
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into();
    let full = format!("{url}{path}");
    let response = match method {
        "GET" => headers.iter().fold(agent.get(&full), |r, (k, v)| r.header(k, v)).call(),
        "DELETE" => headers.iter().fold(agent.delete(&full), |r, (k, v)| r.header(k, v)).call(),
        "POST" => headers.iter().fold(agent.post(&full), |r, (k, v)| r.header(k, v)).send(&body[..]),
        "PUT" => headers.iter().fold(agent.put(&full), |r, (k, v)| r.header(k, v)).send(&body[..]),
        other => bail!("no {other} requests to an edge"),
    };
    let mut response = response.map_err(|err| anyhow!("{url}: {err}"))?;
    let status = response.status().as_u16();
    let text = response.body_mut().read_to_string().map_err(|err| anyhow!("{url}: {err}"))?;
    let answer: Value = serde_json::from_str(&text).map_err(|_| anyhow!("{url} answered {status} with something that isn't JSON; is it a harar edge?"))?;
    if !(200..300).contains(&status) {
        let code = answer["error"].as_str().unwrap_or("error");
        let message = answer["message"].as_str().unwrap_or("no reason given");
        bail!("{url} refused ({status} {code}): {message}");
    }
    Ok(answer)
}

/// `/v1/secrets/<path>`, each segment kept as it is (the edge checks them).
fn secret_path(path: &str) -> Result<String> {
    if path.is_empty() || path.starts_with('/') || path.split('/').any(|s| s.is_empty() || s == "." || s == "..") {
        bail!("{path:?} is not a secret path (prod/shop/STRIPE_KEY)");
    }
    Ok(format!("/v1/secrets/{path}"))
}

// ------------------------------------------------------------------ log

fn log(cmd: Log) -> Result<()> {
    let edge = Paired::find(&cmd.target)?;
    let mut rows: Vec<Value> = Vec::new();
    let mut after = cmd.after;
    loop {
        let page = edge.call("GET", &format!("/v1/log?after={after}"), None)?;
        let batch = page["log"].as_array().cloned().unwrap_or_default();
        let n = batch.len();
        if let Some(last) = batch.last() {
            after = last["seq"].as_u64().ok_or_else(|| anyhow!("a log row without a seq"))?;
        }
        rows.extend(batch);
        if n < 1000 {
            break;
        }
    }
    let chain = match check_chain(&rows) {
        Ok(()) => json!("intact"),
        Err(seq) => json!(format!("broken at seq {seq}")),
    };
    print_json(&json!({ "chain": chain, "log": rows }))
}

/// Each row's hash is sha256(prev_hash "\n" JSON [seq, at, actor, action,
/// resource, decision, reason, ip]), and each row's prev_hash is the hash
/// before it (docs/edge.md §6). Err is the first row that disagrees.
fn check_chain(rows: &[Value]) -> std::result::Result<(), u64> {
    let mut prev: Option<String> = None;
    for row in rows {
        let seq = row["seq"].as_u64().unwrap_or(0);
        let prev_hash = row["prev_hash"].as_str().unwrap_or("");
        if prev.as_deref().is_some_and(|p| p != prev_hash) {
            return Err(seq);
        }
        let fields = json!([row["seq"], row["at"], row["actor"], row["action"], row["resource"], row["decision"], row["reason"], row["ip"]]);
        let want = hex(&Sha256::digest(format!("{prev_hash}\n{fields}").as_bytes()));
        if row["hash"].as_str() != Some(want.as_str()) {
            return Err(seq);
        }
        prev = Some(want);
    }
    Ok(())
}

// ------------------------------------------------------------------ the edge key

#[derive(Debug, Args)]
struct Recover {
    /// Use the recovery code (asked for, never an argument) and the copy on
    /// the edge, instead of this Mac's sealed copy.
    #[arg(long)]
    with_code: bool,
    /// Write the key to this new 0600 file instead of stdout.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Write HARAR_EDGE_KEY=<key>, for `supabase secrets set --env-file`.
    #[arg(long)]
    env: bool,
    /// The recovery code, with --with-code: a no-echo prompt, or stdin.
    #[command(flatten)]
    code: SecretInput,
    #[command(flatten)]
    target: Target,
}

/// A key's id, as the edge's /v1/health reports it: the first 16 hex of
/// sha256("harar-edge-key-id\n" || key) (edge/harar-edge.ts keyId).
fn key_id(raw: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"harar-edge-key-id\n");
    hasher.update(raw);
    hex(&hasher.finalize())[..16].to_owned()
}

/// The id of the key the edge has, or None when it has no usable key.
fn edge_key_status(url: &str) -> Result<Option<String>> {
    let health = send(url, "GET", "/v1/health", None, None)?;
    Ok(match (health["key"]["ready"].as_bool(), health["key"]["id"].as_str()) {
        (Some(true), Some(id)) => Some(id.to_owned()),
        _ => None,
    })
}

fn read_key_file(path: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let text = zeroize::Zeroizing::new(fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?);
    let raw = zeroize::Zeroizing::new(STANDARD.decode(text.trim()).with_context(|| format!("{} is not base64", path.display()))?);
    if raw.len() != 32 {
        bail!("{} is not a 32-byte edge key", path.display());
    }
    Ok(raw)
}

/// `raw` encrypted with the recovery code (age, scrypt), base64.
fn seal_with_code(code: &str, raw: &[u8]) -> Result<String> {
    let normal = harar::recovery::normalize_code(code, RECOVERY_CODE_LEN).ok_or_else(|| anyhow!("not a recovery code"))?;
    let recipient = age::scrypt::Recipient::new(age::secrecy::SecretString::from(normal));
    let sealed = age::encrypt(&recipient, raw).map_err(|err| anyhow!("encrypt the edge key's recovery copy: {err}"))?;
    Ok(STANDARD.encode(sealed))
}

fn open_with_code(code: &str, sealed: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let normal = harar::recovery::normalize_code(code, RECOVERY_CODE_LEN)
        .ok_or_else(|| anyhow!("that isn't a recovery code: it has {RECOVERY_CODE_LEN} letters and digits, in groups of four"))?;
    let identity = age::scrypt::Identity::new(age::secrecy::SecretString::from(normal));
    let bytes = STANDARD.decode(sealed.trim()).context("the edge's recovery copy is not base64")?;
    let raw = zeroize::Zeroizing::new(age::decrypt(&identity, &bytes).map_err(|_| anyhow!("the recovery code doesn't open this edge's recovery copy"))?);
    if raw.len() != 32 {
        bail!("the recovery copy doesn't hold a 32-byte edge key");
    }
    Ok(raw)
}

fn recover(cmd: Recover) -> Result<()> {
    let edge = Paired::find(&cmd.target)?;
    let (raw, from) = match (&edge.edge_key, cmd.with_code) {
        (Some(sealed), false) => (open_sealed_here(&edge, sealed)?, "this Mac's Secure Enclave"),
        _ => {
            let copy = edge.call("GET", "/v1/recovery", None)?;
            let sealed = copy["sealed"].as_str().ok_or_else(|| anyhow!("{} sent no recovery copy", edge.url))?.to_owned();
            let code = zeroize::Zeroizing::new(cmd.code.read("Recovery code")?);
            (open_with_code(&code, &sealed)?, "the recovery code and the edge's copy")
        }
    };
    let id = key_id(&raw);
    let edge_has = match edge_key_status(&edge.url)? {
        Some(theirs) if theirs == id => "this key: nothing to restore",
        Some(_) => "a different key: setting this one makes its secrets readable again",
        None => "no key: set this one",
    };
    let key = zeroize::Zeroizing::new(STANDARD.encode(&raw[..]));
    let text = zeroize::Zeroizing::new(if cmd.env { format!("HARAR_EDGE_KEY={}\n", *key) } else { key.to_string() });
    let report = json!({ "ok": true, "edge": edge.url, "from": from, "key_id": id, "edge_has": edge_has });
    match &cmd.out {
        Some(path) => {
            write_private(path, &text)?;
            let mut report = report;
            report["written"] = json!(path);
            print_json(&report)
        }
        None if std::io::stdout().is_terminal() => {
            bail!("refusing to print the edge key to a terminal; pipe it (harar edge recover | npx wrangler secret put HARAR_EDGE_KEY) or use --out <file>")
        }
        None => {
            std::io::stdout().write_all(text.as_bytes())?;
            std::io::stdout().flush()?;
            eprintln!("{report}");
            Ok(())
        }
    }
}

#[cfg(target_os = "macos")]
fn open_sealed_here(edge: &Paired, sealed: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    match edge.key()? {
        DeviceKey::Enclave(key) => key.open(&STANDARD.decode(sealed)?),
        DeviceKey::File(_) => bail!("this edge's sealed key copy needs its Secure Enclave key"),
    }
}

#[cfg(not(target_os = "macos"))]
fn open_sealed_here(_: &Paired, _: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    bail!("this edge's key copy is sealed to a Mac's Secure Enclave; use --with-code")
}

// ------------------------------------------------------------------ bits

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: gethostname writes at most buf.len() bytes into buf.
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0;
    let name = if ok { String::from_utf8_lossy(&buf[..buf.iter().position(|&b| b == 0).unwrap_or(buf.len())]).into_owned() } else { String::new() };
    let name = name.split('.').next().unwrap_or("").to_owned();
    if name.is_empty() { "this-machine".into() } else { name }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_writes_every_platform_file_with_the_placeholders_filled() {
        for platform in [Platform::Cloudflare, Platform::Vercel, Platform::Supabase] {
            let files = edge_files(platform, &[("HARAR_SETUP_CODE_HASH", "abc123"), ("HARAR_LOG_SINK", "https://sink")]).unwrap();
            assert_eq!(files[0].1, files::CORE, "the core comes first, unchanged");
            let entry = files.iter().find(|(p, _)| p.ends_with(".ts") && p != &files[0].0).expect("an entry file");
            assert!(entry.1.contains(r#"const SETUP_CODE_HASH = "abc123";"#), "{}", platform.name());
            assert!(entry.1.contains(r#"const LOG_SINK = "https://sink";"#), "{}", platform.name());
            for (path, text) in &files {
                for placeholder in ["__HARAR_SETUP_CODE_HASH__", "__HARAR_LOG_SINK__"] {
                    assert!(!text.contains(placeholder), "{path} still has {placeholder}");
                }
            }
        }
        let supabase: Vec<_> = edge_files(Platform::Supabase, &[]).unwrap().into_iter().map(|(p, _)| p).collect();
        assert!(supabase.contains(&"supabase/functions/harar-edge/harar-edge.ts".to_owned()));
        assert!(supabase.contains(&"supabase/functions/harar-edge/index.ts".to_owned()));
    }

    #[test]
    fn a_file_key_signs_what_its_public_key_verifies() {
        use p256::ecdsa::signature::Verifier;
        let key = DeviceKey::File(SigningKey::random(&mut OsRng));
        let raw = key.public_key().unwrap();
        assert_eq!((raw.len(), raw[0]), (65, 4));
        let signature = key.sign(b"harar-edge-v1\nGET\n/v1/secrets").unwrap();
        let verifying = VerifyingKey::from_sec1_bytes(&raw).unwrap();
        verifying.verify(b"harar-edge-v1\nGET\n/v1/secrets", &Signature::from_slice(&signature).unwrap()).unwrap();
        assert!(verifying.verify(b"harar-edge-v1\nGET\n/v1/tokens", &Signature::from_slice(&signature).unwrap()).is_err());
    }

    #[test]
    fn the_chain_check_matches_the_edges_hashing_and_finds_an_edit() {
        // Two rows hashed the way edge/harar-edge.ts does.
        let mut rows = Vec::new();
        let mut prev = String::new();
        for (seq, action) in [(1, "pair"), (2, "secret.put")] {
            let fields = json!([seq, "2026-11-08T12:00:00.000Z", "anonymous", action, "r", "allow", "", "203.0.113.7"]);
            let hash = hex(&Sha256::digest(format!("{prev}\n{fields}").as_bytes()));
            rows.push(json!({ "seq": seq, "at": "2026-11-08T12:00:00.000Z", "actor": "anonymous", "action": action, "resource": "r", "decision": "allow", "reason": "", "ip": "203.0.113.7", "prev_hash": prev, "hash": hash }));
            prev = rows.last().unwrap()["hash"].as_str().unwrap().to_owned();
        }
        assert_eq!(check_chain(&rows), Ok(()));
        rows[1]["resource"] = json!("other");
        assert_eq!(check_chain(&rows), Err(2));
    }

    #[test]
    fn the_recovery_code_opens_its_copy_of_the_edge_key_and_nothing_else_does() {
        let raw = [7u8; 32];
        let code = harar::recovery::new_code(RECOVERY_CODE_LEN);
        assert_eq!(code.len(), RECOVERY_CODE_LEN + RECOVERY_CODE_LEN / 4 - 1, "groups of four: {code}");
        let sealed = seal_with_code(&code, &raw).unwrap();
        assert!(!sealed.contains(&STANDARD.encode(raw)), "the copy isn't the key");
        assert_eq!(&open_with_code(&code, &sealed).unwrap()[..], &raw[..]);
        // As typed from paper: no dashes, upper case, O for 0, L for 1.
        let typed: String = code.chars().filter(|c| *c != '-').map(|c| match c {
            '0' => 'O',
            '1' => 'L',
            c => c.to_ascii_uppercase(),
        }).collect();
        assert_eq!(&open_with_code(&typed, &sealed).unwrap()[..], &raw[..]);
        let other = harar::recovery::new_code(RECOVERY_CODE_LEN);
        assert!(open_with_code(&other, &sealed).unwrap_err().to_string().contains("doesn't open"));
        assert!(open_with_code("abcd-efgh", &sealed).unwrap_err().to_string().contains("isn't a recovery code"));
    }

    #[test]
    fn the_key_id_is_the_edges() {
        // Known answer, computed with Node's crypto the way edge/harar-edge.ts
        // keyId does, for 32 zero bytes. pair compares these two ids.
        assert_eq!(key_id(&[0u8; 32]), "826f32b3bdadd362");
        assert_ne!(key_id(&[0u8; 32]), key_id(&[1u8; 32]));
    }

    #[test]
    fn urls_are_https_or_this_machine() {
        assert!(check_url("https://harar-edge.x.workers.dev").is_ok());
        assert!(check_url("http://127.0.0.1:8787").is_ok());
        assert!(check_url("http://localhost").is_ok());
        assert!(check_url("http://localhost.evil.example").is_err());
        assert!(check_url("http://edge.example").is_err());
        assert!(secret_path("../x").is_err());
        assert_eq!(secret_path("prod/shop/STRIPE_KEY").unwrap(), "/v1/secrets/prod/shop/STRIPE_KEY");
    }
}
