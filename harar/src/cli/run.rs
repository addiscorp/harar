use crate::cli::{SocketArgs, print_json};
use crate::dotenv::{self, Line};
use crate::mask::Masker;
use anyhow::{Context, Result, anyhow};
use clap::Args;
use harar_client::VaultClient;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Run a command with `harar://` references resolved to their values.
///
/// References come from the environment and from `--env-file` files. The
/// command only starts once every reference resolved. Values that show up in
/// its output are replaced with `<concealed by harar>`.
#[derive(Debug, Args)]
pub struct Run {
    #[command(flatten)]
    socket: SocketArgs,
    /// A .env file to load (may repeat; later files win).
    #[arg(long = "env-file", value_name = "PATH")]
    env_files: Vec<PathBuf>,
    /// Pass the command's output through untouched, keeping its terminal.
    #[arg(long)]
    no_masking: bool,
    /// Inside a CI run: load this environment's build secrets, as its env
    /// rule allows, using the run token in --run-token-env.
    #[arg(long)]
    env: Option<String>,
    /// The variable holding the run token. It is not passed to the command.
    #[arg(long, default_value = "HARAR_RUN_TOKEN", requires = "env")]
    run_token_env: String,
    /// Inside a VM: get the environment from the host over vsock instead of
    /// with a run token. The host knows which VM is asking.
    #[arg(long, requires = "env")]
    from_host: bool,
    #[command(flatten)]
    host: crate::cli::vm::HostAddress,
    #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
    command: Vec<String>,
}

pub async fn run(cmd: Run) -> Result<()> {
    let mut env: BTreeMap<String, String> = std::env::vars().collect();
    for path in &cmd.env_files {
        let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let lines = dotenv::parse(&text).with_context(|| format!("parse {}", path.display()))?;
        for entry in dotenv::entries(&lines) {
            env.insert(entry.name.clone(), entry.value.clone());
        }
    }

    let client = VaultClient::from_socket_path(cmd.socket.socket);
    let mut secrets = Vec::new();
    // In a run, the run's environment is all there is: references resolve
    // within it, and nothing else in the vault is reachable.
    let released = match &cmd.env {
        None => None,
        Some(name) if cmd.from_host => {
            let released = crate::cli::vm::secrets_from_host(name, &cmd.host)
                .await
                .with_context(|| format!("the {name} environment's secrets"))?;
            for (name, value) in released_names(&released)? {
                secrets.push(value.clone().into_bytes());
                env.insert(name, value);
            }
            Some(released)
        }
        Some(name) => {
            let token = env
                .remove(&cmd.run_token_env)
                .ok_or_else(|| anyhow!("--env needs the run token in {}", cmd.run_token_env))?;
            let released = client
                .run_secrets(&token, name)
                .await
                .with_context(|| format!("the {name} environment's secrets"))?;
            for (name, value) in released_names(&released)? {
                secrets.push(value.clone().into_bytes());
                env.insert(name, value);
            }
            Some(released)
        }
    };
    for (name, value) in env.iter_mut() {
        if let Some(key) = dotenv::reference(value) {
            let resolved = match &released {
                Some(released) => released
                    .get(key)
                    .cloned()
                    .ok_or_else(|| anyhow!("{name} refers to {value}, which this run's environment doesn't include"))?,
                None => client
                    .get(key)
                    .await
                    .with_context(|| format!("{name} refers to {value}, which could not be read"))?,
            };
            secrets.push(resolved.clone().into_bytes());
            *value = resolved;
        }
    }

    let (program, args) = cmd.command.split_first().expect("clap requires a command");
    let mut command = tokio::process::Command::new(program);
    command.args(args).env_clear().envs(&env);
    if cmd.no_masking || secrets.is_empty() {
        let status = command.status().await.with_context(|| format!("start {program}"))?;
        exit_like(status);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().with_context(|| format!("start {program}"))?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let out = tokio::spawn(copy_masked(stdout, tokio::io::stdout(), Masker::new(secrets.clone())));
    let err = tokio::spawn(copy_masked(stderr, tokio::io::stderr(), Masker::new(secrets)));

    // Ctrl-C reaches the command directly from the terminal. harar stays up
    // so the command's last output is still masked.
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let status = loop {
        tokio::select! {
            status = child.wait() => break status?,
            _ = sigint.recv() => {}
            _ = sigterm.recv() => {
                if let Some(pid) = child.id() {
                    // SAFETY: kill has no memory-safety preconditions.
                    unsafe { libc::kill(pid as i32, libc::SIGTERM) };
                }
            }
        }
    };
    out.await??;
    err.await??;
    exit_like(status);
}

/// Environment variable names for released keys: each key's last segment.
fn released_names(released: &BTreeMap<String, String>) -> Result<BTreeMap<String, String>> {
    let mut names = BTreeMap::new();
    for (key, value) in released {
        let name = key.rsplit('/').next().unwrap_or(key);
        if names.insert(name.to_string(), value.clone()).is_some() {
            return Err(anyhow!("two released keys end in {name}; rename one"));
        }
    }
    Ok(names)
}

async fn copy_masked<R, W>(mut from: R, mut to: W, mut masker: Masker) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 8192];
    loop {
        let read = from.read(&mut buf).await?;
        let chunk = if read == 0 { masker.finish() } else { masker.push(&buf[..read]) };
        to.write_all(&chunk).await?;
        to.flush().await?;
        if read == 0 {
            return Ok(());
        }
    }
}

fn exit_like(status: std::process::ExitStatus) -> ! {
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
    std::process::exit(code)
}

/// Move a .env file's values into the vault and rewrite it with references.
#[derive(Debug, Args)]
pub struct Import {
    #[command(flatten)]
    socket: SocketArgs,
    /// The .env file.
    file: PathBuf,
    /// Vault folder for the values. Default: `dev/<name of the file's folder>`.
    #[arg(long)]
    prefix: Option<String>,
    /// Store the values but leave the file as it is.
    #[arg(long)]
    keep: bool,
}

pub async fn import(cmd: Import) -> Result<()> {
    let text = fs::read_to_string(&cmd.file).with_context(|| format!("read {}", cmd.file.display()))?;
    let mut lines = dotenv::parse(&text).with_context(|| format!("parse {}", cmd.file.display()))?;
    let prefix = match cmd.prefix {
        Some(prefix) => prefix.trim_matches('/').to_string(),
        None => default_prefix(&cmd.file)?,
    };
    let client = VaultClient::from_socket_path(cmd.socket.socket);

    let mut stored = Vec::new();
    for line in &mut lines {
        let Line::Entry(entry) = line else { continue };
        if entry.value.is_empty() || dotenv::reference(&entry.value).is_some() {
            continue;
        }
        let key = format!("{prefix}/{}", entry.name);
        client.put(&key, &entry.value).await.with_context(|| {
            format!("store {} as {key}; {} was not changed", entry.name, cmd.file.display())
        })?;
        entry.set_value(format!("{}{key}", dotenv::REFERENCE_PREFIX));
        stored.push(key);
    }

    if !cmd.keep && !stored.is_empty() {
        replace_file(&cmd.file, &dotenv::render(&lines))?;
    }
    print_json(&serde_json::json!({
        "ok": true,
        "stored": stored,
        "rewritten": !cmd.keep && !stored.is_empty(),
        "file": cmd.file,
    }))
}

fn default_prefix(file: &Path) -> Result<String> {
    let absolute = fs::canonicalize(file).with_context(|| format!("resolve {}", file.display()))?;
    let folder = absolute
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("can't name a vault folder for {}; pass --prefix", file.display()))?;
    Ok(format!("dev/{folder}"))
}

/// Atomically replaces `path`, keeping its permissions.
fn replace_file(path: &Path, contents: &str) -> Result<()> {
    let mode = fs::metadata(path)?.permissions().mode();
    let tmp = path.with_extension(format!("harar-tmp-{}", std::process::id()));
    fs::write(&tmp, contents).with_context(|| format!("write {}", tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

/// Fill `{{ harar://key }}` placeholders in a template.
#[derive(Debug, Args)]
pub struct Inject {
    #[command(flatten)]
    socket: SocketArgs,
    /// Template file.
    #[arg(short = 'i', long = "in")]
    input: PathBuf,
    /// Output file, written with mode 0600. Default: standard output.
    #[arg(short = 'o', long = "out")]
    output: Option<PathBuf>,
}

pub async fn inject(cmd: Inject) -> Result<()> {
    let template = fs::read_to_string(&cmd.input).with_context(|| format!("read {}", cmd.input.display()))?;
    let client = VaultClient::from_socket_path(cmd.socket.socket);
    let mut values = BTreeMap::new();
    for key in crate::template::references(&template).with_context(|| format!("parse {}", cmd.input.display()))? {
        let value = client
            .get(&key)
            .await
            .with_context(|| format!("harar://{key} could not be read"))?;
        values.insert(key, value);
    }
    let filled = crate::template::fill(&template, |key| values.get(key).cloned())?;
    match cmd.output {
        None => {
            use std::io::Write;
            std::io::stdout().write_all(filled.as_bytes())?;
        }
        Some(path) => write_private(&path, &filled)?,
    }
    Ok(())
}

/// Atomically writes `path` with mode 0600, whatever was there before.
fn write_private(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension(format!("harar-tmp-{}", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("create {}", tmp.display()))?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    fs::rename(&tmp, path).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}
