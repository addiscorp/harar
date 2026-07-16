use crate::cli::print_json;
use anyhow::Result;
use clap::Args;
use tana_cli_core::{LinkhashClient, TokenStore, validate_linkhash_origin};

const LINKHASH_HOSTS: &[&str] = &["git.tana.gg", "linkha.sh"];

#[derive(Debug, Args)]
pub struct Whoami {
    #[arg(long, default_value = "https://git.tana.gg")]
    linkhash_url: String,
}

pub async fn run(cmd: Whoami) -> Result<()> {
    validate_harar_linkhash_url(&cmd.linkhash_url)?;
    let store = TokenStore::default_store()?;
    let principal = LinkhashClient::new(cmd.linkhash_url)?.whoami_from_store(&store)?;
    print_json(&serde_json::json!({ "ok": true, "principal": principal }))
}

pub(crate) fn validate_harar_linkhash_url(value: &str) -> Result<()> {
    let url = validate_linkhash_origin(value)?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Linkhash URL has no host"))?;
    if url.scheme() != "https"
        || !LINKHASH_HOSTS
            .iter()
            .any(|allowed| host.eq_ignore_ascii_case(allowed))
    {
        anyhow::bail!("Linkhash URL must use HTTPS and name an approved Linkhash host");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_untrusted_or_cleartext_linkhash_origins_before_any_bearer_request() {
        assert!(validate_harar_linkhash_url("https://git.tana.gg").is_ok());
        assert!(validate_harar_linkhash_url("http://attacker").is_err());
        assert!(validate_harar_linkhash_url("https://attacker.example").is_err());
        assert!(validate_harar_linkhash_url("http://127.0.0.1:9418").is_err());
    }
}
