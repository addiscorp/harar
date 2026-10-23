//! The issuer's rules: which OS users speak as which workloads, and what each
//! workload may ask for. The rules are one vault entry, so they are encrypted
//! and replicated with everything else.

use harar_client::oidc::{
    Actor, DEFAULT_TTL_SECONDS, Grant, IdentityPolicy, IdentityRequest, MAX_TTL_SECONDS, TokenAsk,
    Workload,
};
use std::collections::{BTreeMap, HashMap};

pub const POLICY_KEY: &str = "harar:identity";
const MAX_NAME_LEN: usize = 256;

pub fn load(keys: &HashMap<String, String>) -> Result<IdentityPolicy, &'static str> {
    match keys.get(POLICY_KEY) {
        None => Ok(IdentityPolicy::default()),
        Some(text) => serde_json::from_str(text).map_err(|_| "identity_policy_corrupt"),
    }
}

pub fn store(policy: &IdentityPolicy) -> String {
    serde_json::to_string(policy).expect("identity policy serializes")
}

/// Registers `user` as `sub`. Adding a subject again moves it to the new user.
pub fn add_workload(policy: &mut IdentityPolicy, workload: Workload) -> Result<(), &'static str> {
    valid_subject(&workload.sub)?;
    if workload.user.is_empty() || workload.user.len() > MAX_NAME_LEN || workload.user.contains(char::is_whitespace) {
        return Err("invalid_user");
    }
    for pattern in &workload.sessions_for {
        valid_pattern(pattern)?;
    }
    if policy.workloads.iter().any(|w| w.user == workload.user && w.sub != workload.sub) {
        return Err("user_already_a_workload");
    }
    policy.workloads.retain(|w| w.sub != workload.sub);
    policy.workloads.push(workload);
    policy.workloads.sort_by(|a, b| a.sub.cmp(&b.sub));
    Ok(())
}

/// Removes a workload and everything granted to it.
pub fn remove_workload(policy: &mut IdentityPolicy, sub: &str) -> bool {
    let before = policy.workloads.len() + policy.grants.len();
    policy.workloads.retain(|w| w.sub != sub);
    policy.grants.retain(|g| g.sub != sub);
    before != policy.workloads.len() + policy.grants.len()
}

/// Adds to what `grant.sub` may ask of `grant.audience`.
pub fn grant(policy: &mut IdentityPolicy, grant: Grant) -> Result<(), &'static str> {
    valid_subject(&grant.sub)?;
    valid_audience(&grant.audience)?;
    for pattern in grant.scopes.iter().chain(&grant.may_act_for) {
        valid_pattern(pattern)?;
    }
    let existing = match policy
        .grants
        .iter_mut()
        .find(|g| g.sub == grant.sub && g.audience == grant.audience)
    {
        Some(existing) => existing,
        None => {
            policy.grants.push(Grant { scopes: vec![], may_act_for: vec![], ..grant.clone() });
            policy.grants.last_mut().expect("just pushed")
        }
    };
    for (into, from) in [(&mut existing.scopes, grant.scopes), (&mut existing.may_act_for, grant.may_act_for)] {
        into.extend(from);
        into.sort();
        into.dedup();
    }
    policy.grants.sort_by(|a, b| (&a.sub, &a.audience).cmp(&(&b.sub, &b.audience)));
    Ok(())
}

pub fn ungrant(policy: &mut IdentityPolicy, sub: &str, audience: &str) -> bool {
    let before = policy.grants.len();
    policy.grants.retain(|g| !(g.sub == sub && g.audience == audience));
    before != policy.grants.len()
}

/// Decides what the OS user `user` gets for `ask`, or why it gets nothing.
pub fn decide(policy: &IdentityPolicy, user: &str, ask: &TokenAsk) -> Result<IdentityRequest, &'static str> {
    let workload = policy
        .workloads
        .iter()
        .find(|w| w.user == user)
        .ok_or("not_a_workload")?;
    let grant = policy
        .grants
        .iter()
        .find(|g| g.sub == workload.sub && g.audience == ask.audience)
        .ok_or("audience_not_granted")?;
    let mut scopes = Vec::new();
    for scope in &ask.scopes {
        valid_scope(scope)?;
        if !grant.scopes.iter().any(|pattern| matches(pattern, scope)) {
            return Err("scope_not_granted");
        }
        if !scopes.contains(scope) {
            scopes.push(scope.clone());
        }
    }
    if let Some(act) = &ask.act {
        valid_actor(act)?;
        if !grant.may_act_for.iter().any(|pattern| matches(pattern, &act.sub)) {
            return Err("act_not_granted");
        }
    }
    let ttl_seconds = ask.ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
    if ttl_seconds == 0 || ttl_seconds > MAX_TTL_SECONDS {
        return Err("ttl_out_of_bounds");
    }
    Ok(IdentityRequest {
        sub: workload.sub.clone(),
        aud: ask.audience.clone(),
        scopes,
        ttl_seconds,
        act: ask.act.clone(),
        extra: BTreeMap::new(),
    })
}

/// An exact value, or a prefix ending in `*`.
fn matches(pattern: &str, value: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => value.starts_with(prefix),
        None => pattern == value,
    }
}

fn name_chars(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'@' | b'/' | b':'))
}

/// `kind:name`, such as `svc:gild@demon` or `agent:ava`.
pub(crate) fn valid_subject(sub: &str) -> Result<(), &'static str> {
    let ok = sub.len() <= MAX_NAME_LEN
        && name_chars(sub)
        && sub.split_once(':').is_some_and(|(kind, name)| !kind.is_empty() && !name.is_empty());
    if ok { Ok(()) } else { Err("invalid_subject") }
}

fn valid_actor(act: &Actor) -> Result<(), &'static str> {
    if act.act.is_some() {
        return Err("act_chain_not_allowed");
    }
    valid_subject(&act.sub)?;
    match &act.sid {
        Some(sid) if sid.is_empty() || sid.len() > MAX_NAME_LEN || !name_chars(sid) => Err("invalid_session"),
        _ => Ok(()),
    }
}

fn valid_audience(audience: &str) -> Result<(), &'static str> {
    let ok = !audience.is_empty() && audience.len() <= MAX_NAME_LEN && !audience.contains(char::is_whitespace);
    if ok { Ok(()) } else { Err("invalid_audience") }
}

pub(crate) fn valid_scope(scope: &str) -> Result<(), &'static str> {
    let ok = !scope.is_empty() && scope.len() <= MAX_NAME_LEN && name_chars(scope);
    if ok { Ok(()) } else { Err("invalid_scope") }
}

pub(crate) fn valid_pattern(pattern: &str) -> Result<(), &'static str> {
    let body = pattern.strip_suffix('*').unwrap_or(pattern);
    let ok = pattern.len() <= MAX_NAME_LEN && !pattern.is_empty() && name_chars(body);
    if ok { Ok(()) } else { Err("invalid_pattern") }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMIEN: &str = "https://api.simien.dev";

    fn gild_policy() -> IdentityPolicy {
        let mut policy = IdentityPolicy::default();
        add_workload(&mut policy, Workload { sub: "svc:gild@demon".into(), user: "gild".into(), sessions_for: vec![] }).unwrap();
        grant(
            &mut policy,
            Grant {
                sub: "svc:gild@demon".into(),
                audience: SIMIEN.into(),
                scopes: vec!["deploy:*".into()],
                may_act_for: vec!["agent:*".into()],
            },
        )
        .unwrap();
        policy
    }

    fn ask(scopes: &[&str]) -> TokenAsk {
        TokenAsk {
            audience: SIMIEN.into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            ttl_seconds: None,
            act: None,
            alg: None,
        }
    }

    fn ava() -> Actor {
        Actor { sub: "agent:ava".into(), sid: Some("s_123".into()), act: None }
    }

    #[test]
    fn a_granted_workload_gets_a_five_minute_token_as_itself() {
        let request = decide(&gild_policy(), "gild", &TokenAsk { act: Some(ava()), ..ask(&["deploy:staging"]) }).unwrap();
        assert_eq!(request.sub, "svc:gild@demon");
        assert_eq!(request.aud, SIMIEN);
        assert_eq!(request.scopes, vec!["deploy:staging"]);
        assert_eq!(request.ttl_seconds, DEFAULT_TTL_SECONDS);
        assert_eq!(request.act, Some(ava()));
    }

    #[test]
    fn everything_not_granted_is_refused() {
        let policy = gild_policy();
        assert_eq!(decide(&policy, "mallory", &ask(&[])), Err("not_a_workload"));
        assert_eq!(
            decide(&policy, "gild", &TokenAsk { audience: "https://gild.gg".into(), ..ask(&[]) }),
            Err("audience_not_granted")
        );
        assert_eq!(decide(&policy, "gild", &ask(&["admin:all"])), Err("scope_not_granted"));
        assert_eq!(decide(&policy, "gild", &ask(&["deploy:*"])), Err("invalid_scope"));
        let sami = Actor { sub: "user:sami".into(), sid: None, act: None };
        assert_eq!(decide(&policy, "gild", &TokenAsk { act: Some(sami), ..ask(&[]) }), Err("act_not_granted"));
        let nested = Actor { act: Some(Box::new(Actor { sub: "user:sami".into(), sid: None, act: None })), ..ava() };
        assert_eq!(decide(&policy, "gild", &TokenAsk { act: Some(nested), ..ask(&[]) }), Err("act_chain_not_allowed"));
        for ttl in [0, MAX_TTL_SECONDS + 1] {
            assert_eq!(decide(&policy, "gild", &TokenAsk { ttl_seconds: Some(ttl), ..ask(&[]) }), Err("ttl_out_of_bounds"));
        }
    }

    #[test]
    fn grants_merge_and_removing_a_workload_removes_its_grants() {
        let mut policy = gild_policy();
        grant(
            &mut policy,
            Grant { sub: "svc:gild@demon".into(), audience: SIMIEN.into(), scopes: vec!["logs:read".into(), "deploy:*".into()], may_act_for: vec![] },
        )
        .unwrap();
        assert_eq!(policy.grants.len(), 1);
        assert_eq!(policy.grants[0].scopes, vec!["deploy:*", "logs:read"]);
        assert_eq!(policy.grants[0].may_act_for, vec!["agent:*"]);

        assert!(ungrant(&mut policy.clone(), "svc:gild@demon", SIMIEN));
        assert!(remove_workload(&mut policy, "svc:gild@demon"));
        assert!(policy.grants.is_empty() && policy.workloads.is_empty());
        assert!(!remove_workload(&mut policy, "svc:gild@demon"));
    }

    #[test]
    fn one_user_speaks_as_one_subject() {
        let mut policy = gild_policy();
        assert_eq!(
            add_workload(&mut policy, Workload { sub: "svc:other".into(), user: "gild".into(), sessions_for: vec![] }),
            Err("user_already_a_workload")
        );
        add_workload(&mut policy, Workload { sub: "svc:gild@demon".into(), user: "gild2".into(), sessions_for: vec![] }).unwrap();
        assert_eq!(decide(&policy, "gild", &ask(&[])), Err("not_a_workload"));
        assert!(decide(&policy, "gild2", &ask(&[])).is_ok());
    }

    #[test]
    fn names_are_checked() {
        let mut policy = IdentityPolicy::default();
        for sub in ["gild", ":x", "svc:", "svc:has space", "svc:a\"b"] {
            assert!(add_workload(&mut policy, Workload { sub: sub.into(), user: "u".into(), sessions_for: vec![] }).is_err(), "{sub}");
        }
        let bad = Grant { sub: "svc:a".into(), audience: "has space".into(), scopes: vec![], may_act_for: vec![] };
        assert_eq!(grant(&mut policy, bad), Err("invalid_audience"));
        let bad = Grant { sub: "svc:a".into(), audience: SIMIEN.into(), scopes: vec!["a*b".into()], may_act_for: vec![] };
        assert_eq!(grant(&mut policy, bad), Err("invalid_pattern"));
    }

    #[test]
    fn the_policy_round_trips_through_its_vault_entry() {
        let policy = gild_policy();
        let keys = HashMap::from([(POLICY_KEY.to_string(), store(&policy))]);
        assert_eq!(load(&keys).unwrap(), policy);
        assert_eq!(load(&HashMap::new()).unwrap(), IdentityPolicy::default());
        let corrupt = HashMap::from([(POLICY_KEY.to_string(), "{".to_string())]);
        assert_eq!(load(&corrupt), Err("identity_policy_corrupt"));
    }
}
