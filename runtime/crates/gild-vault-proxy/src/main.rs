use std::ffi::OsString;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow};
use gild_vault_client::VaultClient;
use gild_vault_proxy::{AppState, app};

const DEFAULT_PORT: u16 = 9444;
pub const DEFAULT_SOCKET_PATH: &str = "/run/gild-vault/sock";

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env_and_args()?;
    let vault = VaultClient::from_socket_path(&config.socket_path);
    smoke_check_vault(&vault, &config.socket_path).await?;

    let listener = tokio::net::TcpListener::bind(config.addr)
        .await
        .with_context(|| format!("bind {}", config.addr))?;
    let state = AppState::new(config.token, vault);

    axum::serve(listener, app(state))
        .await
        .context("serve gild-vault-proxy")
}

async fn smoke_check_vault(vault: &VaultClient, socket_path: &Path) -> Result<()> {
    vault.health().await.with_context(|| {
        format!(
            "gild-vault health check failed on socket {}; refusing to bind",
            socket_path.display()
        )
    })?;
    Ok(())
}

#[derive(Debug)]
struct Config {
    addr: SocketAddr,
    socket_path: PathBuf,
    token: String,
}

impl Config {
    fn from_env_and_args() -> Result<Self> {
        let mut port = env_u16("VAULT_PROXY_PORT").unwrap_or(DEFAULT_PORT);
        let mut bind = std::env::var("VAULT_PROXY_BIND").ok();
        let mut socket_path = vault_socket_path_from_env();

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--port" => {
                    let value = args
                        .next()
                        .ok_or_else(|| anyhow!("--port requires a value"))?;
                    port = value.parse().context("parse --port")?;
                }
                "--bind" | "--addr" => {
                    bind = Some(
                        args.next()
                            .ok_or_else(|| anyhow!("{arg} requires a value"))?,
                    );
                }
                "--socket" => {
                    socket_path = PathBuf::from(
                        args.next()
                            .ok_or_else(|| anyhow!("--socket requires a value"))?,
                    );
                }
                _ => {}
            }
        }

        let ip = match bind {
            Some(value) => value.parse().context("parse bind address")?,
            None => tailscale_ip().unwrap_or(IpAddr::from([127, 0, 0, 1])),
        };

        Ok(Self {
            addr: SocketAddr::new(ip, port),
            socket_path,
            token: load_token()?,
        })
    }
}

pub fn vault_socket_path_from_env() -> PathBuf {
    vault_socket_path_from_env_vars(
        std::env::var_os("VAULT_SOCKET"),
        std::env::var_os("GILD_VAULT_SOCKET"),
    )
}

pub fn vault_socket_path_from_env_vars(
    vault_socket: Option<OsString>,
    gild_vault_socket: Option<OsString>,
) -> PathBuf {
    vault_socket
        .or(gild_vault_socket)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH))
}

fn load_token() -> Result<String> {
    if let Ok(token) = std::env::var("VAULT_PROXY_TOKEN") {
        let token = token.trim().to_string();
        if !token.is_empty() {
            return Ok(token);
        }
    }

    let path = std::env::var("VAULT_PROXY_TOKEN_FILE")
        .context("VAULT_PROXY_TOKEN or VAULT_PROXY_TOKEN_FILE must be set")?;
    let token = std::fs::read_to_string(&path)
        .with_context(|| format!("read VAULT_PROXY_TOKEN_FILE {path}"))?
        .trim()
        .to_string();
    if token.is_empty() {
        Err(anyhow!("vault proxy token is empty"))
    } else {
        Ok(token)
    }
}

fn env_u16(name: &str) -> Option<u16> {
    std::env::var(name).ok()?.parse().ok()
}

fn tailscale_ip() -> Option<IpAddr> {
    let output = Command::new("tailscale").args(["ip", "-4"]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    stdout.lines().next()?.trim().parse().ok()
}
