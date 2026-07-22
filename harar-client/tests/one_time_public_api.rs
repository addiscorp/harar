//! External-crate compile contract for the Linkhash custody consumer.

use harar_client::{ConsumeOnceRequest, PurgeOnceRequest, StageOnceRequest, VaultClient};

#[test]
fn one_time_custody_api_is_public_and_callable() {
    let client = VaultClient::from_socket_path("/tmp/harar-client-contract.sock");
    let stage = StageOnceRequest {
        token_id: "token-contract".to_string(),
        principal_id: "principal-contract".to_string(),
        display_id: "display-contract".to_string(),
        value: "non-secret-contract-value".to_string(),
        ttl_seconds: 60,
    };
    let consume = ConsumeOnceRequest {
        token_id: "token-contract".to_string(),
        principal_id: "principal-contract".to_string(),
        display_id: "display-contract".to_string(),
    };
    let purge = PurgeOnceRequest {
        token_id: "token-contract".to_string(),
        principal_id: "principal-contract".to_string(),
        display_id: "display-contract".to_string(),
    };

    // Construct, but do not poll, the requests: this is a public API contract
    // test and must not connect to a socket or handle a custody value.
    drop(client.stage_once(&stage));
    drop(client.consume_once(&consume));
    drop(client.purge_once(&purge));
}
