//! Runs against a real harar edge when edge/test/clients-e2e.sh names one
//! (HARAR_TEST_EDGE_URL, HARAR_TEST_EDGE_TOKEN: test tooling only), and
//! passes without checking anything otherwise.
#![cfg(feature = "edge")]

#[tokio::test]
async fn a_live_edge_resolves_what_the_token_may_read_and_refuses_the_rest() {
    let (Ok(url), Ok(token)) = (std::env::var("HARAR_TEST_EDGE_URL"), std::env::var("HARAR_TEST_EDGE_TOKEN")) else {
        eprintln!("no live edge (edge/test/clients-e2e.sh sets one)");
        return;
    };
    let harar = harar::edge(&url, &token).unwrap();
    assert_eq!(harar.secrets().resolve("harar://prod/shop/STRIPE_KEY").await.unwrap(), "sk_live_e2e");
    let refused = harar.secrets().resolve("harar://prod/site/DATABASE_URL").await.unwrap_err().to_string();
    assert!(refused.starts_with("harar refused: harar://prod/site/DATABASE_URL: not_allowed"), "{refused}");
}
