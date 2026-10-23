//! The vault's side of the egress broker: which services exist, who may use
//! them, the placeholders handed to VMs, and agents' requests for more. A
//! broker asks [`resolve`] on every request, so a revoked session or a removed
//! grant stops working on the next call.

use crate::identity::{matches, valid_pattern, valid_subject};
use crate::sessions::{self, Sessions};
use harar_client::broker::{
    AccessRequest, BrokerGrant, BrokerService, BrokerState, Placeholder, RequestStatus, Resolved, placeholder_hash,
};
use std::collections::HashMap;

pub const BROKER_KEY: &str = "harar:broker";
const MAX_REASON_LEN: usize = 500;
/// Approvals last an hour unless the approver says otherwise.
pub const DEFAULT_APPROVAL_SECONDS: u64 = 3600;

pub fn load(keys: &HashMap<String, String>) -> Result<BrokerState, &'static str> {
    match keys.get(BROKER_KEY) {
        None => Ok(BrokerState::default()),
        Some(text) => serde_json::from_str(text).map_err(|_| "broker_state_corrupt"),
    }
}

pub fn store(state: &BrokerState) -> String {
    serde_json::to_string(state).expect("broker state serializes")
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Adds a service, or replaces the one with the same name.
pub fn add_service(state: &mut BrokerState, service: BrokerService) -> Result<(), &'static str> {
    if !valid_name(&service.name) {
        return Err("invalid_service_name");
    }
    let upstream_ok = (service.upstream.starts_with("https://") || service.upstream.starts_with("http://"))
        && !service.upstream.contains(char::is_whitespace);
    if !upstream_ok {
        return Err("invalid_upstream");
    }
    let header_ok = !service.header.is_empty()
        && service.header.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if !header_ok {
        return Err("invalid_header");
    }
    if service.secret.is_empty() || service.secret.starts_with("harar:") {
        return Err("invalid_secret");
    }
    state.services.retain(|s| s.name != service.name);
    state.services.push(service);
    state.services.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(())
}

/// Removes a service with its grants and placeholders.
pub fn remove_service(state: &mut BrokerState, name: &str) -> bool {
    let before = state.services.len();
    state.services.retain(|s| s.name != name);
    state.grants.retain(|g| g.service != name);
    state.placeholders.retain(|_, p| p.service != name);
    before != state.services.len()
}

pub fn allow(state: &mut BrokerState, grant: BrokerGrant) -> Result<(), &'static str> {
    if !state.services.iter().any(|s| s.name == grant.service) {
        return Err("unknown_service");
    }
    valid_pattern(&grant.to)?;
    if !state.grants.contains(&grant) {
        state.grants.push(grant);
    }
    Ok(())
}

pub fn disallow(state: &mut BrokerState, grant: &BrokerGrant) -> bool {
    let before = state.grants.len();
    state.grants.retain(|g| g != grant);
    before != state.grants.len()
}

/// Lets the workload `sub` resolve placeholders.
pub fn trust(state: &mut BrokerState, sub: String) -> Result<(), &'static str> {
    valid_subject(&sub)?;
    if !state.brokers.contains(&sub) {
        state.brokers.push(sub);
    }
    Ok(())
}

/// A new placeholder for `service` in the live session `sid`. Only its hash
/// is kept; the caller hands the placeholder itself to the VM.
pub fn placeholder(
    state: &mut BrokerState,
    sessions: &Sessions,
    sid: &str,
    service: &str,
    placeholder: &str,
    now: u64,
) -> Result<(), &'static str> {
    if !state.services.iter().any(|s| s.name == service) {
        return Err("unknown_service");
    }
    if !sessions::is_live(sessions, sid, now) {
        return Err("session_not_live");
    }
    prune(state, sessions, now);
    state.placeholders.insert(
        placeholder_hash(placeholder),
        Placeholder { sid: sid.to_string(), service: service.to_string(), created_at: now },
    );
    Ok(())
}

/// An agent in session `sid` asks for `service`.
pub fn request(
    state: &mut BrokerState,
    sessions: &Sessions,
    sid: &str,
    service: &str,
    reason: &str,
    id: String,
    now: u64,
) -> Result<AccessRequest, &'static str> {
    if !state.services.iter().any(|s| s.name == service) {
        return Err("unknown_service");
    }
    if !sessions::is_live(sessions, sid, now) {
        return Err("session_not_live");
    }
    let reason = reason.trim();
    if reason.is_empty() || reason.len() > MAX_REASON_LEN {
        return Err("invalid_reason");
    }
    let request = AccessRequest {
        id: id.clone(),
        sid: sid.to_string(),
        sub: sessions[sid].sub.clone(),
        service: service.to_string(),
        reason: reason.to_string(),
        created_at: now,
        status: RequestStatus::Pending,
        approved_until: None,
    };
    prune(state, sessions, now);
    state.requests.insert(id, request.clone());
    Ok(request)
}

/// Approves (for `for_seconds`, never past the session's end) or denies a
/// pending request.
pub fn decide(
    state: &mut BrokerState,
    sessions: &Sessions,
    id: &str,
    approve: bool,
    for_seconds: Option<u64>,
    now: u64,
) -> Result<AccessRequest, &'static str> {
    let request = state.requests.get_mut(id).ok_or("not_found")?;
    if request.status != RequestStatus::Pending {
        return Err("already_decided");
    }
    if approve {
        let session_end = sessions.get(&request.sid).map_or(now, |s| s.expires_at);
        let for_seconds = for_seconds.unwrap_or(DEFAULT_APPROVAL_SECONDS);
        if for_seconds == 0 {
            return Err("ttl_out_of_bounds");
        }
        request.status = RequestStatus::Approved;
        request.approved_until = Some((now + for_seconds).min(session_end));
    } else {
        request.status = RequestStatus::Denied;
    }
    Ok(request.clone())
}

fn granted(state: &BrokerState, sid: &str, sub: &str, service: &str, now: u64) -> bool {
    state.grants.iter().any(|g| g.service == service && matches(&g.to, sub))
        || state.requests.values().any(|r| {
            r.sid == sid
                && r.service == service
                && r.status == RequestStatus::Approved
                && r.approved_until.is_some_and(|until| until > now)
        })
}

/// What `placeholder` stands for, asked by the broker workload `broker` for a
/// request to `service`.
pub fn resolve(
    state: &BrokerState,
    sessions: &Sessions,
    keys: &HashMap<String, String>,
    broker: &str,
    placeholder: &str,
    service: &str,
    now: u64,
) -> Result<Resolved, &'static str> {
    if !state.brokers.iter().any(|b| b == broker) {
        return Err("not_a_broker");
    }
    let held = state.placeholders.get(&placeholder_hash(placeholder)).ok_or("unknown_placeholder")?;
    if held.service != service {
        return Err("wrong_service");
    }
    if !sessions::is_live(sessions, &held.sid, now) {
        return Err("session_not_live");
    }
    let sub = &sessions[&held.sid].sub;
    if !granted(state, &held.sid, sub, service, now) {
        return Err("not_granted");
    }
    let config = state.services.iter().find(|s| s.name == service).ok_or("unknown_service")?;
    let value = keys.get(&config.secret).ok_or("secret_missing")?;
    Ok(Resolved {
        sid: held.sid.clone(),
        sub: sub.clone(),
        upstream: config.upstream.clone(),
        header: config.header.clone(),
        bearer: config.bearer,
        value: value.clone(),
    })
}

/// Forgets placeholders and requests whose session is gone.
fn prune(state: &mut BrokerState, sessions: &Sessions, now: u64) {
    state.placeholders.retain(|_, p| sessions.contains_key(&p.sid));
    state.requests.retain(|_, r| sessions.contains_key(&r.sid) || r.created_at + 24 * 3600 > now);
}

#[cfg(test)]
mod tests {
    use super::*;
    use harar_client::oidc::{Grant, IdentityPolicy, SessionGrant, SessionStartAsk, Workload};

    const NOW: u64 = 1_800_000_000;
    const PH: &str = "harar-ph-test";

    fn sessions() -> Sessions {
        let policy = IdentityPolicy {
            workloads: vec![Workload { sub: "svc:gild".into(), user: "gild".into(), sessions_for: vec!["agent:*".into()], runs_for: vec![] }],
            grants: vec![Grant { sub: "svc:gild".into(), audience: "https://gild.gg".into(), scopes: vec![], may_act_for: vec![], hardware_only: false }],
        };
        let mut all = Sessions::new();
        let ask = SessionStartAsk {
            sub: "agent:ava".into(),
            for_sub: Some("user:sami".into()),
            ttl_seconds: Some(3600),
            grants: vec![SessionGrant { audience: "https://gild.gg".into(), scopes: vec![] }],
        };
        sessions::start(&policy, &mut all, "gild", &ask, "s_ava".into(), NOW).unwrap();
        all
    }

    fn anthropic() -> BrokerService {
        BrokerService {
            name: "anthropic".into(),
            upstream: "https://api.anthropic.com".into(),
            header: "x-api-key".into(),
            bearer: false,
            secret: "dev/anthropic/key".into(),
        }
    }

    fn state() -> BrokerState {
        let mut state = BrokerState::default();
        add_service(&mut state, anthropic()).unwrap();
        trust(&mut state, "svc:broker".into()).unwrap();
        state
    }

    fn keys() -> HashMap<String, String> {
        HashMap::from([("dev/anthropic/key".to_string(), "sk-real".to_string())])
    }

    #[test]
    fn a_granted_placeholder_resolves_to_the_real_key() {
        let all = sessions();
        let mut state = state();
        allow(&mut state, BrokerGrant { service: "anthropic".into(), to: "agent:*".into() }).unwrap();
        placeholder(&mut state, &all, "s_ava", "anthropic", PH, NOW).unwrap();
        assert!(!store(&state).contains(PH), "only the hash is stored");

        let resolved = resolve(&state, &all, &keys(), "svc:broker", PH, "anthropic", NOW + 1).unwrap();
        assert_eq!(resolved.value, "sk-real");
        assert_eq!(resolved.upstream, "https://api.anthropic.com");
        assert_eq!(resolved.sub, "agent:ava");
    }

    #[test]
    fn resolving_refuses_everything_else() {
        let mut all = sessions();
        let mut state = state();
        placeholder(&mut state, &all, "s_ava", "anthropic", PH, NOW).unwrap();
        let try_resolve = |state: &BrokerState, all: &Sessions, broker: &str, ph: &str, service: &str| {
            resolve(state, all, &keys(), broker, ph, service, NOW + 1).unwrap_err()
        };
        assert_eq!(try_resolve(&state, &all, "svc:broker", PH, "anthropic"), "not_granted");
        allow(&mut state, BrokerGrant { service: "anthropic".into(), to: "agent:bob".into() }).unwrap();
        assert_eq!(try_resolve(&state, &all, "svc:broker", PH, "anthropic"), "not_granted");
        allow(&mut state, BrokerGrant { service: "anthropic".into(), to: "agent:ava".into() }).unwrap();
        assert_eq!(try_resolve(&state, &all, "svc:gild", PH, "anthropic"), "not_a_broker");
        assert_eq!(try_resolve(&state, &all, "svc:broker", "harar-ph-guess", "anthropic"), "unknown_placeholder");
        assert_eq!(try_resolve(&state, &all, "svc:broker", PH, "stripe"), "wrong_service");
        assert!(resolve(&state, &all, &HashMap::new(), "svc:broker", PH, "anthropic", NOW + 1) == Err("secret_missing"));

        sessions::revoke(&mut all, "s_ava", NOW + 1);
        assert_eq!(try_resolve(&state, &all, "svc:broker", PH, "anthropic"), "session_not_live");
    }

    #[test]
    fn an_approved_request_grants_that_session_for_a_while() {
        let all = sessions();
        let mut state = state();
        placeholder(&mut state, &all, "s_ava", "anthropic", PH, NOW).unwrap();
        let asked = request(&mut state, &all, "s_ava", "anthropic", "run eval suite", "r_1".into(), NOW).unwrap();
        assert_eq!(asked.status, RequestStatus::Pending);
        assert!(resolve(&state, &all, &keys(), "svc:broker", PH, "anthropic", NOW + 1).is_err(), "pending is not granted");

        let approved = decide(&mut state, &all, "r_1", true, Some(600), NOW + 10).unwrap();
        assert_eq!(approved.approved_until, Some(NOW + 610));
        assert!(resolve(&state, &all, &keys(), "svc:broker", PH, "anthropic", NOW + 11).is_ok());
        assert_eq!(resolve(&state, &all, &keys(), "svc:broker", PH, "anthropic", NOW + 610), Err("not_granted"));
        assert_eq!(decide(&mut state, &all, "r_1", false, None, NOW + 20), Err("already_decided"));

        // Approval never outlives the session (an hour here).
        request(&mut state, &all, "s_ava", "anthropic", "again", "r_2".into(), NOW).unwrap();
        let long = decide(&mut state, &all, "r_2", true, Some(24 * 3600), NOW).unwrap();
        assert_eq!(long.approved_until, Some(NOW + 3600));

        request(&mut state, &all, "s_ava", "anthropic", "no", "r_3".into(), NOW).unwrap();
        assert_eq!(decide(&mut state, &all, "r_3", false, None, NOW).unwrap().status, RequestStatus::Denied);
        assert_eq!(request(&mut state, &all, "s_ava", "anthropic", "  ", "r_4".into(), NOW), Err("invalid_reason"));
    }

    #[test]
    fn services_are_checked_and_removing_one_removes_its_grants() {
        let mut state = state();
        for bad in [
            BrokerService { name: "Bad Name".into(), ..anthropic() },
            BrokerService { upstream: "ftp://x".into(), ..anthropic() },
            BrokerService { header: "x api key".into(), ..anthropic() },
            BrokerService { secret: "harar:identity".into(), ..anthropic() },
        ] {
            assert!(add_service(&mut state, bad).is_err());
        }
        allow(&mut state, BrokerGrant { service: "anthropic".into(), to: "agent:*".into() }).unwrap();
        assert_eq!(allow(&mut state, BrokerGrant { service: "stripe".into(), to: "agent:*".into() }), Err("unknown_service"));
        let all = sessions();
        placeholder(&mut state, &all, "s_ava", "anthropic", PH, NOW).unwrap();
        assert!(remove_service(&mut state, "anthropic"));
        assert!(state.grants.is_empty() && state.placeholders.is_empty());
    }
}
