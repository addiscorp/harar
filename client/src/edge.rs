//! A vault at a harar edge (docs/edge.md), for a service off your network:
//! it resolves `harar://` references with a service token from
//! `harar edge token create`, and only those the token may read.
//!
//! ```no_run
//! # async fn run(token: &str) -> Result<(), harar::VaultClientError> {
//! let harar = harar::edge("https://harar-edge.you.workers.dev", token)?;
//! let key = harar.secrets().resolve("harar://prod/shop/STRIPE_KEY").await?;
//! # Ok(()) }
//! ```
//!
//! One POST of `/v1/resolve`, all or nothing. Errors use the variants the
//! socket vault does: a refusal is [`VaultClientError::Vault`], a bad answer
//! [`VaultClientError::InvalidResponse`], an edge that can't be reached (or
//! a bad URL or token) [`VaultClientError::Io`]. The token is never in one.

use crate::{reference, VaultClientError, MAX_RESPONSE_BYTES};
use serde_json::{json, Value};
use std::io::{Error as IoError, ErrorKind};
use std::time::Duration;

/// How long the edge has to answer.
const TIMEOUT: Duration = Duration::from_secs(60);

/// A harar edge, at `url` (`https://harar-edge.<you>.workers.dev`, or http
/// to this machine), with a service token, read from the platform's secrets.
pub fn edge(url: &str, token: &str) -> Result<EdgeVault, VaultClientError> {
    if !edge_url(url) {
        return Err(invalid("harar::edge: the edge is an https:// URL"));
    }
    if !edge_token(token) {
        return Err(invalid("harar::edge: the token is a harar edge service token (harar edge token create)"));
    }
    Ok(EdgeVault { edge: url.trim_end_matches('/').to_owned(), token: token.to_owned() })
}

/// A vault at a harar edge: it resolves references. `hosts` and `send` are
/// for gateways on harar's local socket.
#[derive(Clone)]
pub struct EdgeVault {
    edge: String,
    token: String,
}

impl std::fmt::Debug for EdgeVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EdgeVault").field("edge", &self.edge).finish_non_exhaustive()
    }
}

impl EdgeVault {
    /// `harar://` references, resolved at the edge.
    pub fn secrets(&self) -> EdgeSecrets<'_> {
        EdgeSecrets { vault: self }
    }
}

/// `harar://` references resolved at a harar edge.
pub struct EdgeSecrets<'a> {
    vault: &'a EdgeVault,
}

impl EdgeSecrets<'_> {
    /// The value `reference` (`harar://prod/shop/STRIPE_KEY`) names.
    pub async fn resolve(&self, reference: &str) -> Result<String, VaultClientError> {
        let mut values = self.resolve_all(&[reference]).await?;
        Ok(values.remove(0))
    }

    /// Each reference's value, in order, from one request: all or nothing.
    pub async fn resolve_all(&self, references: &[&str]) -> Result<Vec<String>, VaultClientError> {
        if references.is_empty() {
            return Ok(Vec::new());
        }
        for r in references {
            if reference(r).is_none() {
                return Err(VaultClientError::Reference((*r).to_owned()));
            }
        }
        let refs: Vec<String> = references.iter().map(|r| (*r).to_owned()).collect();
        let vault = self.vault.clone();
        tokio::task::spawn_blocking(move || ask(&vault, &refs))
            .await
            .map_err(|err| VaultClientError::Io(IoError::other(err.to_string())))?
    }
}

fn ask(vault: &EdgeVault, refs: &[String]) -> Result<Vec<String>, VaultClientError> {
    let what = if refs.len() == 1 { refs[0].clone() } else { format!("{} references", refs.len()) };
    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(TIMEOUT)).build().into();
    let body = serde_json::to_vec(&json!({ "refs": refs })).map_err(VaultClientError::Json)?;
    let mut response = agent
        .post(&format!("{}/v1/resolve", vault.edge))
        .header("content-type", "application/json")
        .header("authorization", &format!("Bearer {}", vault.token))
        .send(&body[..])
        .map_err(|err| unreachable(&vault.edge, &err))?;
    let status = response.status().as_u16();
    let raw = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES as u64)
        .read_to_vec()
        .map_err(|err| match err {
            ureq::Error::BodyExceedsLimit(_) => VaultClientError::InvalidResponse("harar sent too long an answer".into()),
            err => unreachable(&vault.edge, &err),
        })?;
    let answer: Value = serde_json::from_slice(&raw)
        .map_err(|_| VaultClientError::InvalidResponse(format!("harar at {} did not answer with JSON ({status})", vault.edge)))?;
    let Value::Object(answer) = answer else {
        return Err(VaultClientError::InvalidResponse(format!("harar at {} did not answer with an object", vault.edge)));
    };
    if !(200..300).contains(&status) {
        let code = answer.get("error").and_then(Value::as_str).map_or_else(|| status.to_string(), str::to_owned);
        let message = answer.get("message").and_then(Value::as_str).map(|m| format!(": {m}")).unwrap_or_default();
        return Err(VaultClientError::Vault(format!("{what}: {code}{message}")));
    }
    let values: Option<Vec<String>> = answer
        .get("values")
        .and_then(Value::as_array)
        .filter(|list| list.len() == refs.len())
        .and_then(|list| list.iter().map(|v| v.as_str().map(str::to_owned)).collect());
    values.ok_or_else(|| VaultClientError::InvalidResponse(format!("harar sent no value for {what}")))
}

/// Why the edge couldn't be asked, as an I/O error that names the edge.
fn unreachable(edge: &str, err: &ureq::Error) -> VaultClientError {
    let kind = match err {
        ureq::Error::Timeout(_) => ErrorKind::TimedOut,
        _ => ErrorKind::Other,
    };
    VaultClientError::Io(IoError::new(kind, format!("harar at {edge}: {err}")))
}

fn invalid(message: &str) -> VaultClientError {
    VaultClientError::Io(IoError::new(ErrorKind::InvalidInput, message))
}

/// https://, or http:// to this machine only.
fn edge_url(url: &str) -> bool {
    if url.strip_prefix("https://").is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/')) {
        return true;
    }
    ["http://127.0.0.1", "http://localhost", "http://[::1]"]
        .iter()
        .any(|p| url.strip_prefix(p).is_some_and(|rest| rest.is_empty() || rest.starts_with(':') || rest.starts_with('/')))
}

/// `harar_edge_<16 hex>_<43 base64url>`, as `harar edge token create` makes it.
fn edge_token(token: &str) -> bool {
    let Some(rest) = token.strip_prefix("harar_edge_") else { return false };
    let (id, secret) = rest.split_at(rest.len().min(16));
    id.len() == 16
        && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && secret.strip_prefix('_').is_some_and(|s| s.len() == 43 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    const TOKEN: &str = "harar_edge_0123456789abcdef_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    type Asked = Arc<Mutex<Vec<(String, String, String, Value)>>>;

    /// A stand-in edge, mounted under /functions/v1/harar-edge as on
    /// Supabase: one HTTP/1.1 request per connection.
    fn stand_in(reply: impl Fn(&[String]) -> (u16, String) + Send + 'static) -> (String, Asked) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/functions/v1/harar-edge/", listener.local_addr().unwrap());
        let asked: Asked = Arc::default();
        let log = asked.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut conn) = conn else { return };
                let mut reader = BufReader::new(conn.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut parts = line.split(' ');
                let (method, path) = (parts.next().unwrap().to_owned(), parts.next().unwrap().to_owned());
                let (mut auth, mut length) = (String::new(), 0usize);
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    if header == "\r\n" {
                        break;
                    }
                    let (name, value) = header.split_once(':').unwrap();
                    match name.to_ascii_lowercase().as_str() {
                        "authorization" => auth = value.trim().to_owned(),
                        "content-length" => length = value.trim().parse().unwrap(),
                        _ => {}
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let body: Value = serde_json::from_slice(&body).unwrap();
                let refs: Vec<String> = body["refs"].as_array().unwrap().iter().map(|r| r.as_str().unwrap().to_owned()).collect();
                log.lock().unwrap().push((method, path, auth, body));
                let (status, text) = reply(&refs);
                let _ = write!(conn, "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}", text.len());
            }
        });
        (url, asked)
    }

    fn stripe(refs: &[String]) -> (u16, String) {
        let values = [("harar://prod/shop/STRIPE_KEY", "sk_live_real"), ("harar://prod/shop/OTHER", "other")];
        let found: Option<Vec<&str>> = refs.iter().map(|r| values.iter().find(|(k, _)| k == r).map(|(_, v)| *v)).collect();
        match found {
            Some(v) => (200, json!({ "values": v }).to_string()),
            None => (403, json!({ "error": "not_allowed", "message": "this caller may not read prod/site/DATABASE_URL" }).to_string()),
        }
    }

    #[tokio::test]
    async fn an_edge_vault_resolves_with_one_post_of_v1_resolve_the_service_token_as_its_bearer() {
        let (url, asked) = stand_in(stripe);
        let harar = edge(&url, TOKEN).unwrap();
        assert_eq!(harar.secrets().resolve("harar://prod/shop/STRIPE_KEY").await.unwrap(), "sk_live_real");
        assert_eq!(harar.secrets().resolve_all(&["harar://prod/shop/STRIPE_KEY", "harar://prod/shop/OTHER"]).await.unwrap(), ["sk_live_real", "other"]);
        assert!(harar.secrets().resolve_all(&[]).await.unwrap().is_empty());
        let refused = harar.secrets().resolve("harar://prod/site/DATABASE_URL").await.unwrap_err().to_string();
        assert_eq!(refused, "harar refused: harar://prod/site/DATABASE_URL: not_allowed: this caller may not read prod/site/DATABASE_URL");
        for not_one in ["prod/shop/STRIPE_KEY", "op://Prod/Stripe/credential", "harar://", "harar://a b"] {
            assert!(matches!(harar.secrets().resolve(not_one).await, Err(VaultClientError::Reference(_))), "{not_one}");
        }
        let expect = |refs: &[&str]| ("POST".to_owned(), "/functions/v1/harar-edge/v1/resolve".to_owned(), format!("Bearer {TOKEN}"), json!({ "refs": refs }));
        assert_eq!(
            *asked.lock().unwrap(),
            [
                expect(&["harar://prod/shop/STRIPE_KEY"]),
                expect(&["harar://prod/shop/STRIPE_KEY", "harar://prod/shop/OTHER"]),
                expect(&["harar://prod/site/DATABASE_URL"]),
            ]
        );
        assert!(!format!("{harar:?}").contains(&TOKEN[28..]), "Debug leaves the token out");
    }

    #[tokio::test]
    async fn every_way_an_edge_can_fail_is_an_error_naming_why_and_the_token_is_never_in_it() {
        for (status, text, why) in [
            (200, "not json".to_owned(), "did not answer with JSON (200)"),
            (502, "<html>bad gateway</html>".to_owned(), "did not answer with JSON (502)"),
            (200, "[1]".to_owned(), "did not answer with an object"),
            (200, r#"{"values":[]}"#.to_owned(), "no value for"),
            (200, r#"{"values":[7]}"#.to_owned(), "no value for"),
            (401, r#"{"error":"revoked","message":"this token was revoked"}"#.to_owned(), "revoked: this token was revoked"),
            (500, "{}".to_owned(), "harar://a/b: 500"),
            (200, "x".repeat(MAX_RESPONSE_BYTES + 1), "too long an answer"),
        ] {
            let (url, _) = stand_in(move |_| (status, text.clone()));
            let err = edge(&url, TOKEN).unwrap().secrets().resolve("harar://a/b").await.unwrap_err().to_string();
            assert!(err.contains(why), "{err:?} should say {why:?}");
            assert!(!err.contains(&TOKEN[28..]), "the token is in {err:?}");
        }
        let err = edge("http://127.0.0.1:1", TOKEN).unwrap().secrets().resolve("harar://a/b").await.unwrap_err();
        assert!(matches!(&err, VaultClientError::Io(_)) && err.to_string().contains("harar at http://127.0.0.1:1: "), "{err}");
    }

    #[test]
    fn an_edge_is_https_and_its_token_a_harar_edge_token() {
        for (url, token, why) in [
            ("http://edge.example", TOKEN, "the edge is an https:// URL"),
            ("http://localhost.evil.example", TOKEN, "the edge is an https:// URL"),
            ("https://", TOKEN, "the edge is an https:// URL"),
            ("https://edge.example", "", "service token"),
            ("https://edge.example", "sk_live_oops", "service token"),
            ("https://edge.example", "harar_edge_0123456789abcdeF_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "service token"),
        ] {
            let err = edge(url, token).unwrap_err().to_string();
            assert!(err.contains(why), "{url} {token}: {err}");
            assert!(token.is_empty() || !err.contains(token));
        }
        for ok in ["https://harar-edge.you.workers.dev", "http://localhost:8787", "http://127.0.0.1", "http://[::1]:8787/x"] {
            assert!(edge(ok, TOKEN).is_ok(), "{ok}");
        }
    }
}
