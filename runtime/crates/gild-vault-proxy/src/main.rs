use std::ffi::OsString;
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use axum::Extension;
use gild_vault_client::VaultClient;
use gild_vault_proxy::{AppState, RequestPeer, app};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperBuilder;
use hyper_util::service::TowerToHyperService;
use rustls::RootCertStore;
use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use x509_parser::prelude::{FromDer, X509Certificate};

const DEFAULT_PORT: u16 = 9444;
const DEFAULT_AUDIT_LOG_PATH: &str = "/var/log/gild-vault-proxy-audit.log";
pub const DEFAULT_SOCKET_PATH: &str = "/run/gild-vault/sock";

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env_and_args()?;
    let vault = VaultClient::from_socket_path(&config.socket_path);
    smoke_check_vault(&vault, &config.socket_path).await?;

    let mut state = AppState::new(config.token, vault);
    if let Some(audit_log_path) = config.audit_log_path {
        state = state.with_audit_log_path(audit_log_path);
    }

    match (config.plain_addr, config.tls) {
        (Some(plain_addr), Some(tls)) => {
            let plain_state = state.clone();
            let plain = tokio::spawn(async move { serve_plain(plain_addr, plain_state).await });
            let tls = tokio::spawn(async move { serve_tls(tls, state).await });
            tokio::select! {
                result = plain => result.context("plain listener task")??,
                result = tls => result.context("tls listener task")??,
            }
            Ok(())
        }
        (Some(plain_addr), None) => serve_plain(plain_addr, state).await,
        (None, Some(tls)) => serve_tls(tls, state).await,
        (None, None) => Err(anyhow!(
            "at least one of --bind or --tls-bind must be configured"
        )),
    }
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
    plain_addr: Option<SocketAddr>,
    tls: Option<TlsConfig>,
    socket_path: PathBuf,
    token: String,
    audit_log_path: Option<PathBuf>,
}

#[derive(Debug)]
struct TlsConfig {
    addr: SocketAddr,
    ca_path: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
}

impl Config {
    fn from_env_and_args() -> Result<Self> {
        let mut port = env_u16("VAULT_PROXY_PORT").unwrap_or(DEFAULT_PORT);
        let mut bind = std::env::var("VAULT_PROXY_BIND").ok();
        let mut plain_addr = None;
        let mut tls_addr = env_socket_addr("VAULT_PROXY_TLS_BIND")?;
        let mut tls_ca = env_path("VAULT_PROXY_TLS_CA");
        let mut tls_cert = env_path("VAULT_PROXY_TLS_CERT");
        let mut tls_key = env_path("VAULT_PROXY_TLS_KEY");
        let mut socket_path = vault_socket_path_from_env();
        let mut audit_log_path = env_path("VAULT_PROXY_AUDIT_LOG")
            .or_else(|| Some(PathBuf::from(DEFAULT_AUDIT_LOG_PATH)));

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
                "--tls-bind" => {
                    tls_addr = Some(parse_socket_addr(
                        &args
                            .next()
                            .ok_or_else(|| anyhow!("--tls-bind requires a value"))?,
                        DEFAULT_PORT + 1,
                    )?);
                }
                "--tls-ca" => {
                    tls_ca = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| anyhow!("--tls-ca requires a value"))?,
                    ));
                }
                "--tls-cert" => {
                    tls_cert = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| anyhow!("--tls-cert requires a value"))?,
                    ));
                }
                "--tls-key" => {
                    tls_key = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| anyhow!("--tls-key requires a value"))?,
                    ));
                }
                "--socket" => {
                    socket_path = PathBuf::from(
                        args.next()
                            .ok_or_else(|| anyhow!("--socket requires a value"))?,
                    );
                }
                "--audit-log" => {
                    audit_log_path = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| anyhow!("--audit-log requires a value"))?,
                    ));
                }
                "--no-audit-log" => {
                    audit_log_path = None;
                }
                _ => {}
            }
        }

        if let Some(value) = bind {
            plain_addr = Some(parse_socket_addr(&value, port)?);
        } else if tls_addr.is_none() {
            plain_addr = Some(SocketAddr::new(
                tailscale_ip().unwrap_or(IpAddr::from([127, 0, 0, 1])),
                port,
            ));
        }

        let tls = match tls_addr {
            Some(addr) => Some(TlsConfig {
                addr,
                ca_path: tls_ca.ok_or_else(|| anyhow!("--tls-ca is required with --tls-bind"))?,
                cert_path: tls_cert
                    .ok_or_else(|| anyhow!("--tls-cert is required with --tls-bind"))?,
                key_path: tls_key
                    .ok_or_else(|| anyhow!("--tls-key is required with --tls-bind"))?,
            }),
            None => None,
        };

        Ok(Self {
            plain_addr,
            tls,
            socket_path,
            token: load_token()?,
            audit_log_path,
        })
    }
}

async fn serve_plain(addr: SocketAddr, state: AppState) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    serve_accepted(listener, state, None)
        .await
        .context("serve plain gild-vault-proxy")
}

async fn serve_tls(config: TlsConfig, state: AppState) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(config.addr)
        .await
        .with_context(|| format!("bind {}", config.addr))?;
    let acceptor = TlsAcceptor::from(Arc::new(load_tls_config(&config)?));
    loop {
        let (stream, remote_addr) = listener.accept().await.context("accept tls connection")?;
        let acceptor = acceptor.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(err) => {
                    eprintln!("gild-vault-proxy tls handshake failed from {remote_addr}: {err}");
                    return;
                }
            };
            let client_cn = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(client_cert_cn);
            let service = app(state).layer(Extension(RequestPeer {
                remote_addr: Some(remote_addr),
                tls_client_cn: client_cn,
            }));
            let io = TokioIo::new(tls_stream);
            if let Err(err) = HyperBuilder::new(TokioExecutor::new())
                .serve_connection(io, TowerToHyperService::new(service))
                .await
            {
                eprintln!("gild-vault-proxy tls connection error from {remote_addr}: {err}");
            }
        });
    }
}

async fn serve_accepted(
    listener: tokio::net::TcpListener,
    state: AppState,
    tls_client_cn: Option<String>,
) -> Result<()> {
    loop {
        let (stream, remote_addr) = listener.accept().await.context("accept connection")?;
        let state = state.clone();
        let tls_client_cn = tls_client_cn.clone();
        tokio::spawn(async move {
            let service = app(state).layer(Extension(RequestPeer {
                remote_addr: Some(remote_addr),
                tls_client_cn,
            }));
            let io = TokioIo::new(stream);
            if let Err(err) = HyperBuilder::new(TokioExecutor::new())
                .serve_connection(io, TowerToHyperService::new(service))
                .await
            {
                eprintln!("gild-vault-proxy connection error from {remote_addr}: {err}");
            }
        });
    }
}

fn load_tls_config(config: &TlsConfig) -> Result<rustls::ServerConfig> {
    let mut roots = RootCertStore::empty();
    let ca_certs = load_certs(&config.ca_path)?;
    for cert in ca_certs {
        roots.add(cert).context("add client CA certificate")?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("build client certificate verifier")?;
    rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            load_certs(&config.cert_path)?,
            load_private_key(&config.key_path)?,
        )
        .context("load proxy server certificate")
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader =
        BufReader::new(File::open(path).with_context(|| format!("open {}", path.display()))?);
    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parse certificate PEM {}", path.display()))
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader =
        BufReader::new(File::open(path).with_context(|| format!("open {}", path.display()))?);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parse private key PEM {}", path.display()))?
        .ok_or_else(|| anyhow!("{} did not contain a private key", path.display()))
}

fn client_cert_cn(cert: &CertificateDer<'_>) -> Option<String> {
    let (_, parsed) = X509Certificate::from_der(cert.as_ref()).ok()?;
    parsed
        .subject()
        .iter_common_name()
        .next()?
        .as_str()
        .ok()
        .map(ToOwned::to_owned)
}

fn parse_socket_addr(value: &str, default_port: u16) -> Result<SocketAddr> {
    if let Ok(addr) = value.parse() {
        return Ok(addr);
    }
    let ip: IpAddr = value.parse().context("parse bind address")?;
    Ok(SocketAddr::new(ip, default_port))
}

fn env_socket_addr(name: &str) -> Result<Option<SocketAddr>> {
    std::env::var(name)
        .ok()
        .map(|value| parse_socket_addr(&value, DEFAULT_PORT + 1))
        .transpose()
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
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
