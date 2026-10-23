//! OIDC identity tokens: what harar's issuer signs, and the checks a receiver
//! (simien, gild, a cloud) makes before trusting one.
//!
//! Tokens are JWTs signed with ES256, which most clouds accept, or EdDSA. The
//! issuer publishes both public keys in its JWKS and describes itself in a
//! discovery document at `<issuer>/.well-known/openid-configuration`.

use std::collections::BTreeMap;

use ed25519_dalek::Signer as _;
use p256::ecdsa::signature::Verifier as _;
use p256::elliptic_curve::sec1::FromEncodedPoint;

use crate::{Jwk, Jwks, TokenError, b64_url, b64_url_decode, random_jti};

/// What a token lasts when the caller doesn't say.
pub const DEFAULT_TTL_SECONDS: u64 = 300;
/// No identity token lives longer than this, whatever was asked for.
pub const MAX_TTL_SECONDS: u64 = 3600;
/// How far a receiver's clock may run behind the issuer's.
pub const CLOCK_SKEW_SECONDS: u64 = 60;
/// How deep an `act` chain may nest (agent for agent for person …).
pub const MAX_ACTOR_DEPTH: usize = 8;
pub const JWKS_PATH: &str = "/.well-known/jwks.json";
pub const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";

/// Who a token's subject is acting for (RFC 8693 `act`). The outermost actor
/// is the one the subject acts for directly; each nested one is who *that*
/// actor acts for.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Actor {
    pub sub: String,
    /// The actor's session, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<Actor>>,
}

impl Actor {
    pub fn depth(&self) -> usize {
        1 + self.act.as_ref().map_or(0, |inner| inner.depth())
    }

    /// Every subject in the chain, nearest first.
    pub fn chain(&self) -> Vec<&str> {
        let mut out = vec![self.sub.as_str()];
        let mut next = self.act.as_deref();
        while let Some(actor) = next {
            out.push(&actor.sub);
            next = actor.act.as_deref();
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IdentityClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    /// Space-separated scopes (RFC 9068).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
    pub jti: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Actor>,
    /// Anything else the issuer adds, such as a run's repo and commit.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl IdentityClaims {
    pub fn scopes(&self) -> impl Iterator<Item = &str> {
        self.scope.split_whitespace()
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes().any(|granted| granted == scope)
    }
}

/// What the issuer is asked to sign. It fills in `iss`, the times and `jti`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRequest {
    pub sub: String,
    pub aud: String,
    pub scopes: Vec<String>,
    pub ttl_seconds: u64,
    pub act: Option<Actor>,
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Alg {
    ES256,
    EdDSA,
}

impl Alg {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ES256" => Some(Self::ES256),
            "EdDSA" => Some(Self::EdDSA),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::ES256 => "ES256",
            Self::EdDSA => "EdDSA",
        }
    }
}

/// The issuer's signing keys and the URL it signs as.
pub struct Issuer {
    url: String,
    es256: p256::ecdsa::SigningKey,
    ed25519: ed25519_dalek::SigningKey,
}

impl Issuer {
    pub fn new(
        url: impl Into<String>,
        es256: p256::ecdsa::SigningKey,
        ed25519: ed25519_dalek::SigningKey,
    ) -> Self {
        Self {
            url: url.into().trim_end_matches('/').to_string(),
            es256,
            ed25519,
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// The Ed25519 key, which also signs harar's older template tokens.
    pub fn ed25519(&self) -> &ed25519_dalek::SigningKey {
        &self.ed25519
    }

    pub fn jwks(&self) -> Jwks {
        let mut jwks = crate::jwks_for_key(&self.ed25519.verifying_key());
        jwks.keys.insert(0, es256_jwk(self.es256.verifying_key()));
        jwks
    }

    pub fn discovery(&self) -> serde_json::Value {
        discovery_document(&self.url)
    }

    pub fn issue(
        &self,
        request: &IdentityRequest,
        alg: Alg,
        now_epoch_seconds: u64,
    ) -> Result<(String, IdentityClaims), TokenError> {
        if request.ttl_seconds == 0 || request.ttl_seconds > MAX_TTL_SECONDS {
            return Err(TokenError::TtlOutOfBounds {
                cap_seconds: MAX_TTL_SECONDS,
            });
        }
        if request.act.as_ref().is_some_and(|act| act.depth() > MAX_ACTOR_DEPTH) {
            return Err(TokenError::InvalidToken("act chain is too deep".to_string()));
        }
        let claims = IdentityClaims {
            iss: self.url.clone(),
            sub: request.sub.clone(),
            aud: request.aud.clone(),
            scope: request.scopes.join(" "),
            iat: now_epoch_seconds,
            nbf: now_epoch_seconds,
            exp: now_epoch_seconds.saturating_add(request.ttl_seconds),
            jti: random_jti(),
            act: request.act.clone(),
            extra: request.extra.clone(),
        };
        let payload = serde_json::to_vec(&claims).map_err(|err| TokenError::Json(err.to_string()))?;
        let token = match alg {
            Alg::ES256 => {
                let kid = es256_kid(self.es256.verifying_key());
                let signing_input = signing_input("ES256", &kid, &payload)?;
                let signature: p256::ecdsa::Signature = self.es256.sign(signing_input.as_bytes());
                format!("{signing_input}.{}", b64_url(signature.to_bytes()))
            }
            Alg::EdDSA => {
                let kid = crate::key_id(&self.ed25519.verifying_key());
                let signing_input = signing_input("EdDSA", &kid, &payload)?;
                let signature = self.ed25519.sign(signing_input.as_bytes());
                format!("{signing_input}.{}", b64_url(signature.to_bytes()))
            }
        };
        Ok((token, claims))
    }
}

/// A caller asking the issuer for a token. Who the caller is comes from the
/// socket, never from the request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TokenAsk {
    pub audience: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    /// Whom the caller acts for. Only one level: deeper chains come from
    /// sessions the issuer itself knows about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Actor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<Alg>,
}

/// An OS user on the issuer's host that speaks as `sub`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Workload {
    pub sub: String,
    pub user: String,
    /// Subjects it may start sessions for, such as `agent:*`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sessions_for: Vec<String>,
    /// Repos it may register CI runs for, such as `addiscorp/*`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runs_for: Vec<String>,
}

/// One audience a session may reach, and the scopes it may ask for there.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionGrant {
    pub audience: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// An agent's session. A child session can never reach further than its
/// parent, and dies with it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub sid: String,
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// The workload that started it, or for a child, the parent's.
    pub started_by: String,
    /// Who a top-level session acts for, such as `user:sami`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub for_sub: Option<String>,
    pub grants: Vec<SessionGrant>,
    pub created_at: u64,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionStartAsk {
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub for_sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    pub grants: Vec<SessionGrant>,
}

/// Trade a session token for a narrower child: a child session, and a token
/// for one audience.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExchangeAsk {
    pub session_token: String,
    /// The child's name; its subject becomes `<parent sub>/<name>`.
    pub name: String,
    pub audience: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
}

/// What `sub` may ask for from one audience. `scopes` and `may_act_for` hold
/// exact values or prefixes ending in `*`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Grant {
    pub sub: String,
    pub audience: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub may_act_for: Vec<String>,
    /// Refuse requests from hosts whose key is not in hardware.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hardware_only: bool,
}

/// The issuer's rules.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IdentityPolicy {
    #[serde(default)]
    pub workloads: Vec<Workload>,
    #[serde(default)]
    pub grants: Vec<Grant>,
}

/// The claim carrying a session's id in session and exchanged tokens.
pub const SID_CLAIM: &str = "sid";

pub fn discovery_document(issuer: &str) -> serde_json::Value {
    let issuer = issuer.trim_end_matches('/');
    serde_json::json!({
        "issuer": issuer,
        "jwks_uri": format!("{issuer}{JWKS_PATH}"),
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256", "EdDSA"],
        "claims_supported": ["iss", "sub", "aud", "scope", "iat", "nbf", "exp", "jti", "act"],
    })
}

/// Checks a token the way a receiver must: signature against the issuer's
/// JWKS, then issuer, audience, time window and lifetime.
pub fn verify_identity(
    jwks: &Jwks,
    token: &str,
    issuer: &str,
    audience: &str,
    now_epoch_seconds: u64,
) -> Result<IdentityClaims, TokenError> {
    let payload = verify_signature(jwks, token)?;
    let claims: IdentityClaims =
        serde_json::from_slice(&payload).map_err(|err| TokenError::Json(err.to_string()))?;
    if claims.iss != issuer.trim_end_matches('/') {
        return Err(TokenError::InvalidToken("wrong issuer".to_string()));
    }
    if claims.aud != audience {
        return Err(TokenError::WrongAudience);
    }
    if claims.exp <= now_epoch_seconds {
        return Err(TokenError::Expired);
    }
    if claims.nbf > now_epoch_seconds.saturating_add(CLOCK_SKEW_SECONDS) {
        return Err(TokenError::InvalidToken("token is not valid yet".to_string()));
    }
    if claims.exp.saturating_sub(claims.iat) > MAX_TTL_SECONDS {
        return Err(TokenError::InvalidToken("token lives longer than an hour".to_string()));
    }
    if claims.act.as_ref().is_some_and(|act| act.depth() > MAX_ACTOR_DEPTH) {
        return Err(TokenError::InvalidToken("act chain is too deep".to_string()));
    }
    Ok(claims)
}

/// Checks a JWT's signature against `jwks` and returns its payload bytes.
/// Accepts ES256 and EdDSA, and only with a key of the matching type.
pub fn verify_signature(jwks: &Jwks, token: &str) -> Result<Vec<u8>, TokenError> {
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(TokenError::InvalidToken(
            "token must have three JWT segments".to_string(),
        ));
    }
    let header: serde_json::Value = serde_json::from_slice(&b64_url_decode(parts[0])?)
        .map_err(|err| TokenError::Json(err.to_string()))?;
    let alg = header
        .get("alg")
        .and_then(|value| value.as_str())
        .and_then(Alg::parse)
        .ok_or_else(|| TokenError::InvalidToken("token alg must be ES256 or EdDSA".to_string()))?;
    let kid = header
        .get("kid")
        .and_then(|value| value.as_str())
        .ok_or_else(|| TokenError::InvalidToken("missing kid".to_string()))?;
    let jwk = jwks
        .keys
        .iter()
        .find(|key| key.kid == kid)
        .ok_or(TokenError::KeyNotFound)?;
    if jwk.alg != alg.name() {
        return Err(TokenError::InvalidToken("unsupported jwk".to_string()));
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature = b64_url_decode(parts[2])?;
    match alg {
        Alg::EdDSA => {
            if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
                return Err(TokenError::InvalidToken("unsupported jwk".to_string()));
            }
            let key: [u8; 32] = b64_url_decode(&jwk.x)?
                .as_slice()
                .try_into()
                .map_err(|_| TokenError::InvalidToken("bad Ed25519 key".to_string()))?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&key)
                .map_err(|_| TokenError::InvalidToken("bad Ed25519 key".to_string()))?;
            let signature: [u8; 64] = signature
                .as_slice()
                .try_into()
                .map_err(|_| TokenError::InvalidToken("bad signature length".to_string()))?;
            ed25519_dalek::Verifier::verify(
                &key,
                signing_input.as_bytes(),
                &ed25519_dalek::Signature::from_bytes(&signature),
            )
            .map_err(|_| TokenError::BadSignature)?;
        }
        Alg::ES256 => {
            if jwk.kty != "EC" || jwk.crv != "P-256" {
                return Err(TokenError::InvalidToken("unsupported jwk".to_string()));
            }
            let key = p256_key_from_jwk(jwk)?;
            let signature = p256::ecdsa::Signature::from_slice(&signature)
                .map_err(|_| TokenError::InvalidToken("bad signature length".to_string()))?;
            key.verify(signing_input.as_bytes(), &signature)
                .map_err(|_| TokenError::BadSignature)?;
        }
    }
    b64_url_decode(parts[1])
}

pub fn generate_es256_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::random(&mut rand_core::OsRng)
}

pub fn es256_key_from_bytes(bytes: &[u8]) -> Result<p256::ecdsa::SigningKey, TokenError> {
    p256::ecdsa::SigningKey::from_slice(bytes)
        .map_err(|_| TokenError::InvalidToken("ES256 key must be a 32-byte P-256 scalar".to_string()))
}

pub fn es256_key_bytes(key: &p256::ecdsa::SigningKey) -> [u8; 32] {
    key.to_bytes().into()
}

fn es256_coordinates(key: &p256::ecdsa::VerifyingKey) -> (Vec<u8>, Vec<u8>) {
    let point = key.to_encoded_point(false);
    let x = point.x().expect("uncompressed point has x").to_vec();
    let y = point.y().expect("uncompressed point has y").to_vec();
    (x, y)
}

fn es256_kid(key: &p256::ecdsa::VerifyingKey) -> String {
    let (x, _) = es256_coordinates(key);
    format!("harar-es256-{}", &b64_url(x)[..16])
}

fn es256_jwk(key: &p256::ecdsa::VerifyingKey) -> Jwk {
    p256_jwk(es256_kid(key), key)
}

/// The public JWK for a P-256 key, under `kid`.
pub fn p256_jwk(kid: String, key: &p256::ecdsa::VerifyingKey) -> Jwk {
    let (x, y) = es256_coordinates(key);
    Jwk {
        kty: "EC".to_string(),
        kid,
        crv: "P-256".to_string(),
        alg: "ES256".to_string(),
        key_use: "sig".to_string(),
        x: b64_url(x),
        y: Some(b64_url(y)),
    }
}

/// The P-256 key a JWK describes, checked to be a point on the curve.
pub fn p256_key_from_jwk(jwk: &Jwk) -> Result<p256::ecdsa::VerifyingKey, TokenError> {
    let bad = || TokenError::InvalidToken("bad P-256 key".to_string());
    let x: [u8; 32] = b64_url_decode(&jwk.x)?.as_slice().try_into().map_err(|_| bad())?;
    let y: [u8; 32] = b64_url_decode(jwk.y.as_deref().ok_or_else(bad)?)?
        .as_slice()
        .try_into()
        .map_err(|_| bad())?;
    let point = p256::EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false);
    let key = Option::<p256::PublicKey>::from(p256::PublicKey::from_encoded_point(&point)).ok_or_else(bad)?;
    Ok(p256::ecdsa::VerifyingKey::from(key))
}

fn signing_input(alg: &str, kid: &str, payload: &[u8]) -> Result<String, TokenError> {
    let header = serde_json::json!({ "alg": alg, "typ": "JWT", "kid": kid });
    let header = serde_json::to_vec(&header).map_err(|err| TokenError::Json(err.to_string()))?;
    Ok(format!("{}.{}", b64_url(header), b64_url(payload)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://id.example.test";
    const NOW: u64 = 1_800_000_000;

    fn issuer() -> Issuer {
        Issuer::new(ISSUER, generate_es256_key(), crate::generate_signing_key())
    }

    fn request() -> IdentityRequest {
        IdentityRequest {
            sub: "svc:gild@demon".into(),
            aud: "https://api.simien.dev".into(),
            scopes: vec!["deploy:staging".into()],
            ttl_seconds: DEFAULT_TTL_SECONDS,
            act: Some(Actor {
                sub: "agent:ava".into(),
                sid: Some("s_123".into()),
                act: Some(Box::new(Actor { sub: "user:sami".into(), sid: None, act: None })),
            }),
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn both_algorithms_verify_against_the_published_jwks() {
        let issuer = issuer();
        let jwks: Jwks = serde_json::from_value(serde_json::to_value(issuer.jwks()).unwrap()).unwrap();
        for alg in [Alg::ES256, Alg::EdDSA] {
            let (token, issued) = issuer.issue(&request(), alg, NOW).unwrap();
            let claims = verify_identity(&jwks, &token, ISSUER, "https://api.simien.dev", NOW + 1).unwrap();
            assert_eq!(claims, issued);
            assert_eq!(claims.exp, NOW + DEFAULT_TTL_SECONDS);
            assert!(claims.has_scope("deploy:staging"));
            assert_eq!(claims.act.unwrap().chain(), vec!["agent:ava", "user:sami"]);
        }
    }

    #[test]
    fn es256_jwk_is_what_standard_verifiers_expect() {
        let jwks = serde_json::to_value(issuer().jwks()).unwrap();
        let ec = &jwks["keys"][0];
        assert_eq!(ec["kty"], "EC");
        assert_eq!(ec["crv"], "P-256");
        assert_eq!(ec["alg"], "ES256");
        assert_eq!(b64_url_decode(ec["x"].as_str().unwrap()).unwrap().len(), 32);
        assert_eq!(b64_url_decode(ec["y"].as_str().unwrap()).unwrap().len(), 32);
        assert!(jwks["keys"][1].get("y").is_none(), "Ed25519 JWK has no y");
    }

    #[test]
    fn receivers_reject_the_wrong_issuer_audience_time_or_key() {
        let issuer = issuer();
        let jwks = issuer.jwks();
        let (token, _) = issuer.issue(&request(), Alg::ES256, NOW).unwrap();
        let aud = "https://api.simien.dev";

        assert!(verify_identity(&jwks, &token, "https://id.other.test", aud, NOW).is_err());
        assert_eq!(verify_identity(&jwks, &token, ISSUER, "https://gild.gg", NOW), Err(TokenError::WrongAudience));
        assert_eq!(verify_identity(&jwks, &token, ISSUER, aud, NOW + DEFAULT_TTL_SECONDS), Err(TokenError::Expired));
        assert!(verify_identity(&jwks, &token, ISSUER, aud, NOW - CLOCK_SKEW_SECONDS - 1).is_err());
        assert_eq!(verify_identity(&self::issuer().jwks(), &token, ISSUER, aud, NOW), Err(TokenError::KeyNotFound));
    }

    #[test]
    fn tampered_or_mislabelled_tokens_fail() {
        let issuer = issuer();
        let jwks = issuer.jwks();
        let aud = "https://api.simien.dev";
        let (token, _) = issuer.issue(&request(), Alg::ES256, NOW).unwrap();
        let parts: Vec<&str> = token.split('.').collect();

        let mut claims: serde_json::Value = serde_json::from_slice(&b64_url_decode(parts[1]).unwrap()).unwrap();
        claims["scope"] = "deploy:production".into();
        let forged = format!("{}.{}.{}", parts[0], b64_url(serde_json::to_vec(&claims).unwrap()), parts[2]);
        assert_eq!(verify_identity(&jwks, &forged, ISSUER, aud, NOW), Err(TokenError::BadSignature));

        // An ES256 signature presented under the Ed25519 key's kid.
        let ed_kid = &jwks.keys[1].kid;
        let header = b64_url(serde_json::to_vec(&serde_json::json!({"alg": "ES256", "kid": ed_kid})).unwrap());
        let relabelled = format!("{header}.{}.{}", parts[1], parts[2]);
        assert!(verify_identity(&jwks, &relabelled, ISSUER, aud, NOW).is_err());

        let none = format!("{}.{}.", b64_url(br#"{"alg":"none"}"#), parts[1]);
        assert!(verify_identity(&jwks, &none, ISSUER, aud, NOW).is_err());
    }

    #[test]
    fn lifetimes_over_an_hour_are_refused_on_both_sides() {
        let issuer = issuer();
        let mut long = request();
        long.ttl_seconds = MAX_TTL_SECONDS + 1;
        assert!(matches!(issuer.issue(&long, Alg::ES256, NOW), Err(TokenError::TtlOutOfBounds { .. })));
        long.ttl_seconds = 0;
        assert!(issuer.issue(&long, Alg::ES256, NOW).is_err());
        long.ttl_seconds = MAX_TTL_SECONDS;
        assert!(issuer.issue(&long, Alg::ES256, NOW).is_ok());
    }

    #[test]
    fn extra_claims_travel_at_the_top_level() {
        let issuer = issuer();
        let mut run = request();
        run.extra.insert("repo".into(), "addiscorp/site".into());
        let (token, _) = issuer.issue(&run, Alg::EdDSA, NOW).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&b64_url_decode(token.split('.').nth(1).unwrap()).unwrap()).unwrap();
        assert_eq!(payload["repo"], "addiscorp/site");
        let claims = verify_identity(&issuer.jwks(), &token, ISSUER, "https://api.simien.dev", NOW).unwrap();
        assert_eq!(claims.extra["repo"], "addiscorp/site");
    }

    #[test]
    fn discovery_points_at_the_jwks() {
        let doc = issuer().discovery();
        assert_eq!(doc["issuer"], ISSUER);
        assert_eq!(doc["jwks_uri"], format!("{ISSUER}/.well-known/jwks.json"));
        assert_eq!(doc["id_token_signing_alg_values_supported"][0], "ES256");
    }

    #[test]
    fn es256_keys_round_trip_through_bytes() {
        let key = generate_es256_key();
        let again = es256_key_from_bytes(&es256_key_bytes(&key)).unwrap();
        assert_eq!(key.verifying_key(), again.verifying_key());
        assert!(es256_key_from_bytes(&[0u8; 32]).is_err());
    }
}
