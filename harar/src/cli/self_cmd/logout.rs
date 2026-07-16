use super::whoami::validate_harar_linkhash_url;
use crate::cli::print_json;
use anyhow::Result;
use clap::Args;
use tana_cli_core::{LinkhashClient, TokenStore};

#[derive(Debug, Args)]
pub struct Logout {
    #[arg(long, default_value = "https://git.tana.gg")]
    linkhash_url: String,
}

pub async fn run(cmd: Logout) -> Result<()> {
    validate_harar_linkhash_url(&cmd.linkhash_url)?;
    let store = TokenStore::default_store()?;
    logout(&store, &LinkhashClient::new(cmd.linkhash_url)?)?;
    print_json(&serde_json::json!({ "ok": true }))
}

fn logout(store: &TokenStore, client: &LinkhashClient) -> Result<()> {
    let Some(token) = store.read_token()? else {
        return Ok(());
    };
    let token_id = client.whoami(&token)?.token_id.ok_or_else(|| anyhow::anyhow!("Linkhash whoami response omitted token_id; refusing local logout because server revocation cannot be confirmed"))?;
    client.revoke(&token, token_id)?;
    store.remove_token()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use tana_cli_core::SecretToken;

    #[test]
    fn logout_revokes_server_token_before_removing_local_copy() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        thread::spawn(move || {
            let mut revoked = false;
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 4096];
                let count = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..count]);
                assert!(request.contains("authorization: Bearer tg_usr_logout"));
                let (status, body) = if request.starts_with("GET /api/v1/whoami") && !revoked {
                    (
                        "200 OK",
                        r#"{"ok":true,"principal":{"identity":{"id":"sam"},"token_id":42}}"#,
                    )
                } else if request.starts_with("DELETE /api/tokens/42") {
                    revoked = true;
                    ("200 OK", r#"{"status":"revoked"}"#)
                } else {
                    assert!(revoked, "logout must revoke before the token is rejected");
                    ("401 Unauthorized", r#"{"ok":false,"error":"revoked"}"#)
                };
                stream.write_all(format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                ).as_bytes()).unwrap();
            }
        });
        let temp = tempfile::tempdir().unwrap();
        let store = TokenStore::new(temp.path().join("token"));
        store
            .write_token(&SecretToken::new("tg_usr_logout").unwrap())
            .unwrap();
        let client = LinkhashClient::new(base).unwrap();

        logout(&store, &client).unwrap();

        assert!(store.read_token().unwrap().is_none());
        assert!(
            client
                .whoami(&SecretToken::new("tg_usr_logout").unwrap())
                .is_err()
        );
    }
}
