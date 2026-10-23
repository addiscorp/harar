//! The issuer's side of host enrollment (scenario S6): pending enrollments,
//! approval by code, and checking the assertions enrolled hosts sign to get
//! tokens for their workloads.

use crate::identity::valid_subject;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use harar_client::Jwks;
use harar_client::hosts::{EnrollAsk, Host, HostAssertion, HostsState, MAX_ASSERTION_SECONDS, PendingHost, enrollment_code};
use std::collections::HashMap;

pub const HOSTS_KEY: &str = "harar:hosts";
/// Unapproved enrollments are forgotten after an hour.
const PENDING_SECONDS: u64 = 3600;
/// Anyone can ask to enroll, so the queue is short.
const MAX_PENDING: usize = 32;
/// How far ahead of the issuer a host's clock may run.
const CLOCK_SKEW_SECONDS: u64 = 60;

pub fn load(keys: &HashMap<String, String>) -> Result<HostsState, &'static str> {
    match keys.get(HOSTS_KEY) {
        None => Ok(HostsState::default()),
        Some(text) => serde_json::from_str(text).map_err(|_| "hosts_corrupt"),
    }
}

pub fn store(state: &HostsState) -> String {
    serde_json::to_string(state).expect("hosts serialize")
}

fn valid_host_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 63 && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Queues an enrollment and returns its code. The first enrollment under a
/// name holds it until approved or rejected, so nobody can swap in a key
/// after the real host has asked.
pub fn enroll(state: &mut HostsState, ask: EnrollAsk, now: u64) -> Result<String, &'static str> {
    if !valid_host_name(&ask.name) {
        return Err("invalid_host_name");
    }
    let jwk_ok = ask.jwk.kty == "EC"
        && ask.jwk.crv == "P-256"
        && ask.jwk.alg == "ES256"
        && ask.jwk.kid == format!("host:{}", ask.name)
        && harar_client::oidc::p256_key_from_jwk(&ask.jwk).is_ok();
    if !jwk_ok {
        return Err("invalid_host_key");
    }
    state.pending.retain(|_, p| p.created_at + PENDING_SECONDS > now);
    if state.hosts.contains_key(&ask.name) {
        return Err("host_exists");
    }
    if state.pending.contains_key(&ask.name) {
        return Err("name_pending");
    }
    if state.pending.len() >= MAX_PENDING {
        return Err("too_many_pending");
    }
    let code = enrollment_code(&ask.jwk);
    state.pending.insert(
        ask.name.clone(),
        PendingHost { name: ask.name, jwk: ask.jwk, tier: ask.tier, code: code.clone(), created_at: now },
    );
    Ok(code)
}

fn normalize_code(code: &str) -> String {
    code.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_uppercase()
}

/// Approves `name` if `code` is the one its host showed.
pub fn approve(state: &mut HostsState, name: &str, code: &str, now: u64) -> Result<Host, &'static str> {
    let pending = state.pending.get(name).ok_or("not_found")?;
    if pending.created_at + PENDING_SECONDS <= now {
        state.pending.remove(name);
        return Err("not_found");
    }
    if normalize_code(&pending.code) != normalize_code(code) {
        return Err("code_mismatch");
    }
    let pending = state.pending.remove(name).expect("just found");
    let host = Host { name: pending.name, jwk: pending.jwk, tier: pending.tier, approved_at: now };
    state.hosts.insert(host.name.clone(), host.clone());
    Ok(host)
}

pub fn reject(state: &mut HostsState, name: &str) -> bool {
    state.pending.remove(name).is_some()
}

pub fn remove(state: &mut HostsState, name: &str) -> bool {
    state.hosts.remove(name).is_some()
}

/// Checks an assertion an enrolled host signed: its key, the issuer as
/// audience, a short life, a workload of that host, and that it was never
/// used before (`seen` holds used ids until they expire).
pub fn verify_assertion(
    state: &HostsState,
    token: &str,
    issuer: &str,
    seen: &mut HashMap<String, u64>,
    now: u64,
) -> Result<(Host, HostAssertion), &'static str> {
    let header = token.split('.').next().ok_or("invalid_assertion")?;
    let header: serde_json::Value = B64URL
        .decode(header)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or("invalid_assertion")?;
    let name = header
        .get("kid")
        .and_then(|kid| kid.as_str())
        .and_then(|kid| kid.strip_prefix("host:"))
        .ok_or("invalid_assertion")?;
    let host = state.hosts.get(name).ok_or("unknown_host")?;
    let payload = harar_client::oidc::verify_signature(&Jwks { keys: vec![host.jwk.clone()] }, token)
        .map_err(|_| "bad_signature")?;
    let assertion: HostAssertion = serde_json::from_slice(&payload).map_err(|_| "invalid_assertion")?;
    let fresh = assertion.exp > now
        && assertion.iat <= now + CLOCK_SKEW_SECONDS
        && assertion.exp.saturating_sub(assertion.iat) <= MAX_ASSERTION_SECONDS;
    if assertion.iss != format!("host:{name}") || assertion.aud != issuer.trim_end_matches('/') {
        return Err("invalid_assertion");
    }
    if !fresh {
        return Err("assertion_expired");
    }
    valid_subject(&assertion.sub)?;
    if !assertion.sub.ends_with(&format!("@{name}")) {
        return Err("not_this_hosts_workload");
    }
    seen.retain(|_, exp| *exp > now);
    if seen.insert(assertion.jti.clone(), assertion.exp).is_some() {
        return Err("assertion_replayed");
    }
    Ok((host.clone(), assertion))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_key::HostKey;
    use harar_client::hosts::HostTier;
    use harar_client::oidc::TokenAsk;

    const ISSUER: &str = "https://id.example.test";
    const NOW: u64 = 1_800_000_000;

    fn enrolled() -> (HostsState, HostKey) {
        let key = HostKey::create(true).unwrap();
        let mut state = HostsState::default();
        let code = enroll(&mut state, EnrollAsk { name: "bugsy".into(), jwk: key.jwk("bugsy").unwrap(), tier: key.tier() }, NOW).unwrap();
        approve(&mut state, "bugsy", &code.to_lowercase().replace('-', ""), NOW + 5).unwrap();
        (state, key)
    }

    fn assertion(sub: &str, iat: u64) -> HostAssertion {
        HostAssertion {
            iss: "host:bugsy".into(),
            sub: sub.into(),
            aud: ISSUER.into(),
            iat,
            exp: iat + 60,
            jti: harar_client::random_id("a_"),
            ask: TokenAsk { audience: "https://api.simien.dev".into(), scopes: vec![], ttl_seconds: None, act: None, alg: None },
        }
    }

    #[test]
    fn an_approved_host_signs_for_its_own_workloads_once() {
        let (state, key) = enrolled();
        assert_eq!(state.hosts["bugsy"].tier, HostTier::Software);
        let mut seen = HashMap::new();
        let token = key.assert("bugsy", &assertion("svc:gild@bugsy", NOW)).unwrap();
        let (host, asserted) = verify_assertion(&state, &token, ISSUER, &mut seen, NOW + 1).unwrap();
        assert_eq!(host.name, "bugsy");
        assert_eq!(asserted.sub, "svc:gild@bugsy");
        assert_eq!(verify_assertion(&state, &token, ISSUER, &mut seen, NOW + 2), Err("assertion_replayed"));
    }

    #[test]
    fn assertions_are_refused_unless_everything_lines_up() {
        let (mut state, key) = enrolled();
        let mut seen = HashMap::new();
        let check = |state: &HostsState, token: &str, seen: &mut HashMap<String, u64>| verify_assertion(state, token, ISSUER, seen, NOW + 1);

        let other_host = key.assert("bugsy", &assertion("svc:gild@demon", NOW)).unwrap();
        assert_eq!(check(&state, &other_host, &mut seen), Err("not_this_hosts_workload"));
        let old = key.assert("bugsy", &assertion("svc:gild@bugsy", NOW - 120)).unwrap();
        assert_eq!(check(&state, &old, &mut seen), Err("assertion_expired"));
        let mut long = assertion("svc:gild@bugsy", NOW);
        long.exp = NOW + 3600;
        assert_eq!(check(&state, &key.assert("bugsy", &long).unwrap(), &mut seen), Err("assertion_expired"));
        let mut elsewhere = assertion("svc:gild@bugsy", NOW);
        elsewhere.aud = "https://id.other.test".into();
        assert_eq!(check(&state, &key.assert("bugsy", &elsewhere).unwrap(), &mut seen), Err("invalid_assertion"));

        let impostor = HostKey::create(true).unwrap();
        let forged = impostor.assert("bugsy", &assertion("svc:gild@bugsy", NOW)).unwrap();
        assert_eq!(check(&state, &forged, &mut seen), Err("bad_signature"));
        let unknown = impostor.assert("mallory", &assertion("svc:gild@mallory", NOW)).unwrap();
        assert_eq!(check(&state, &unknown, &mut seen), Err("unknown_host"));

        assert!(remove(&mut state, "bugsy"));
        let after = key.assert("bugsy", &assertion("svc:gild@bugsy", NOW)).unwrap();
        assert_eq!(check(&state, &after, &mut seen), Err("unknown_host"));
    }

    #[test]
    fn the_first_enrollment_holds_the_name_and_the_code_must_match() {
        let key = HostKey::create(true).unwrap();
        let attacker = HostKey::create(true).unwrap();
        let mut state = HostsState::default();
        let ask = |key: &HostKey| EnrollAsk { name: "bugsy".into(), jwk: key.jwk("bugsy").unwrap(), tier: key.tier() };
        let code = enroll(&mut state, ask(&key), NOW).unwrap();
        assert_eq!(enroll(&mut state, ask(&attacker), NOW + 1), Err("name_pending"));
        assert_eq!(approve(&mut state, "bugsy", "0000-0000", NOW + 2).unwrap_err(), "code_mismatch");
        assert_eq!(state.pending["bugsy"].jwk, key.jwk("bugsy").unwrap(), "the attacker's key never replaced it");
        approve(&mut state, "bugsy", &code, NOW + 3).unwrap();
        assert_eq!(enroll(&mut state, ask(&attacker), NOW + 4), Err("host_exists"));

        let wrong_kid = EnrollAsk { jwk: key.jwk("demon").unwrap(), ..ask(&key) };
        assert_eq!(enroll(&mut HostsState::default(), wrong_kid, NOW), Err("invalid_host_key"));
        let mut not_a_point = key.jwk("bugsy").unwrap();
        not_a_point.x = "AAAA".into();
        assert_eq!(enroll(&mut HostsState::default(), EnrollAsk { jwk: not_a_point, ..ask(&key) }, NOW), Err("invalid_host_key"));
    }

    #[test]
    fn pending_enrollments_expire_and_the_queue_is_bounded() {
        let mut state = HostsState::default();
        for n in 0..MAX_PENDING {
            let key = HostKey::create(true).unwrap();
            let name = format!("h{n}");
            enroll(&mut state, EnrollAsk { name: name.clone(), jwk: key.jwk(&name).unwrap(), tier: key.tier() }, NOW).unwrap();
        }
        let key = HostKey::create(true).unwrap();
        let ask = EnrollAsk { name: "late".into(), jwk: key.jwk("late").unwrap(), tier: key.tier() };
        assert_eq!(enroll(&mut state, ask.clone(), NOW), Err("too_many_pending"));
        assert!(enroll(&mut state, ask, NOW + PENDING_SECONDS).is_ok(), "expired ones make room");
    }
}
