//! The vsock side of VM identity: one line of JSON each way. Outside the VM,
//! `harar vm serve` answers on a vsock port and tells the issuer which CID
//! asked; the kernel supplies the CID, so a VM can't claim another's. Inside,
//! `harar vm token` and `harar run --from-host` ask over it.

use anyhow::{Result, anyhow};
use harar_client::vms::VmRequest;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

const MAX_LINE: u64 = 64 * 1024;

/// Answers one request on `stream`. `answer` turns it into the reply, given
/// which CID is asking.
pub async fn serve_connection<S, F, Fut>(stream: S, answer: F) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(VmRequest) -> Fut,
    Fut: std::future::Future<Output = serde_json::Value>,
{
    let (read, mut write) = tokio::io::split(stream);
    let mut line = String::new();
    BufReader::new(tokio::io::AsyncReadExt::take(read, MAX_LINE)).read_line(&mut line).await?;
    let reply = match serde_json::from_str::<VmRequest>(&line) {
        Ok(request) => answer(request).await,
        Err(_) => serde_json::json!({ "ok": false, "error": "bad_request" }),
    };
    write.write_all(format!("{reply}\n").as_bytes()).await?;
    write.shutdown().await?;
    Ok(())
}

/// Sends one request and returns the reply, or the host's reason for refusing.
pub async fn ask<S: AsyncRead + AsyncWrite + Unpin>(stream: S, request: &VmRequest) -> Result<serde_json::Value> {
    let (read, mut write) = tokio::io::split(stream);
    write.write_all(format!("{}\n", serde_json::to_string(request)?).as_bytes()).await?;
    let mut line = String::new();
    BufReader::new(tokio::io::AsyncReadExt::take(read, MAX_LINE)).read_line(&mut line).await?;
    let reply: serde_json::Value = serde_json::from_str(&line).map_err(|_| anyhow!("the host sent no answer"))?;
    if reply["ok"] != true {
        return Err(anyhow!("the host refused: {}", reply["error"].as_str().unwrap_or("unknown")));
    }
    Ok(reply)
}

/// The issuer's answer to a VM's request, as the reply line.
pub async fn answer(client: &harar_client::VaultClient, cid: u32, request: VmRequest) -> serde_json::Value {
    let refused = |err: harar_client::VaultClientError| match err {
        harar_client::VaultClientError::Vault(reason) => serde_json::json!({ "ok": false, "error": reason }),
        other => {
            eprintln!("harar vm: issuer unreachable: {other}");
            serde_json::json!({ "ok": false, "error": "issuer_unavailable" })
        }
    };
    match request {
        VmRequest::Token(ask) => match client.vm_token(cid, &ask).await {
            Ok((token, claims)) => serde_json::json!({ "ok": true, "token": token, "claims": claims }),
            Err(err) => refused(err),
        },
        VmRequest::Secrets { env } => match client.vm_secrets(cid, &env).await {
            Ok(secrets) => serde_json::json!({ "ok": true, "secrets": secrets }),
            Err(err) => refused(err),
        },
    }
}

#[cfg(target_os = "linux")]
pub mod vsock {
    use super::*;
    use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

    /// Serves VMs on `port` until the process ends.
    pub async fn serve(port: u32, client: harar_client::VaultClient) -> Result<()> {
        let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port))?;
        eprintln!("harar vm serving on vsock port {port}");
        loop {
            let (stream, peer) = listener.accept().await?;
            let client = client.clone();
            tokio::spawn(async move {
                let cid = peer.cid();
                if let Err(err) = serve_connection(stream, |request| async move { answer(&client, cid, request).await }).await {
                    eprintln!("harar vm: connection from CID {cid}: {err:#}");
                }
            });
        }
    }

    pub async fn connect(cid: u32, port: u32) -> Result<VsockStream> {
        VsockStream::connect(VsockAddr::new(cid, port))
            .await
            .map_err(|err| anyhow!("reach the host over vsock (CID {cid}, port {port}): {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harar_client::oidc::TokenAsk;

    #[tokio::test]
    async fn one_request_one_reply() {
        let (vm, host) = tokio::io::duplex(4096);
        let server = tokio::spawn(serve_connection(host, |request| async move {
            match request {
                VmRequest::Secrets { env } => serde_json::json!({ "ok": true, "secrets": { "env": env } }),
                VmRequest::Token(_) => serde_json::json!({ "ok": false, "error": "not_a_session_vm" }),
            }
        }));
        let reply = ask(vm, &VmRequest::Secrets { env: "production".into() }).await.unwrap();
        assert_eq!(reply["secrets"]["env"], "production");
        server.await.unwrap().unwrap();

        let (vm, host) = tokio::io::duplex(4096);
        tokio::spawn(serve_connection(host, |_| async { serde_json::json!({ "ok": false, "error": "unknown_vm" }) }));
        let ask_token = VmRequest::Token(TokenAsk { audience: "a".into(), scopes: vec![], ttl_seconds: None, act: None, alg: None });
        let err = ask(vm, &ask_token).await.unwrap_err().to_string();
        assert!(err.contains("unknown_vm"), "{err}");
    }

    #[tokio::test]
    async fn garbage_gets_bad_request() {
        let (mut vm, host) = tokio::io::duplex(4096);
        tokio::spawn(serve_connection(host, |_| async { unreachable!("garbage never reaches the issuer") }));
        vm.write_all(b"{not json\n").await.unwrap();
        let mut reply = String::new();
        BufReader::new(vm).read_line(&mut reply).await.unwrap();
        assert!(reply.contains("bad_request"));
    }
}
