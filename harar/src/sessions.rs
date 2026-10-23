//! Agent sessions: who started them, what they may reach, and the tree of
//! child sessions under them. A session is live only while every ancestor is,
//! so revoking one ends everything below it.
//!
//! Like the identity rules, sessions are one vault entry.

use harar_client::oidc::{Actor, IdentityPolicy, IdentityRequest, MAX_ACTOR_DEPTH, Session, SessionGrant, SessionStartAsk};
use crate::identity::matches;
use std::collections::{BTreeMap, HashMap};

pub const SESSIONS_KEY: &str = "harar:sessions";
pub const DEFAULT_SESSION_SECONDS: u64 = 8 * 3600;
pub const MAX_SESSION_SECONDS: u64 = 24 * 3600;
/// Ended sessions are kept this long so `session tree` can still show them.
const KEEP_ENDED_SECONDS: u64 = 24 * 3600;
const MAX_CHILD_NAME_LEN: usize = 64;

pub type Sessions = BTreeMap<String, Session>;

pub fn load(keys: &HashMap<String, String>) -> Result<Sessions, &'static str> {
    match keys.get(SESSIONS_KEY) {
        None => Ok(Sessions::new()),
        Some(text) => serde_json::from_str(text).map_err(|_| "sessions_corrupt"),
    }
}

pub fn store(sessions: &Sessions) -> String {
    serde_json::to_string(sessions).expect("sessions serialize")
}

/// Live: not revoked, not expired, and its parent (if any) is live.
pub fn is_live(sessions: &Sessions, sid: &str, now: u64) -> bool {
    let mut next = Some(sid);
    for _ in 0..=MAX_ACTOR_DEPTH {
        let Some(sid) = next else { return true };
        let Some(session) = sessions.get(sid) else { return false };
        if session.revoked_at.is_some() || session.expires_at <= now {
            return false;
        }
        next = session.parent.as_deref();
    }
    false
}

/// The `act` chain a token gets when it acts for `sid`: the session's
/// subject, then whoever that session acts for, and so on up.
pub fn actor_for(sessions: &Sessions, sid: &str) -> Option<Actor> {
    let session = sessions.get(sid)?;
    Some(Actor { sub: session.sub.clone(), sid: Some(session.sid.clone()), act: chain_above(sessions, session).map(Box::new) })
}

/// Whom `session` acts for: its parent session, or for a top-level session,
/// the subject it was started for.
pub fn chain_above(sessions: &Sessions, session: &Session) -> Option<Actor> {
    match &session.parent {
        Some(parent) => actor_for(sessions, parent),
        None => session.for_sub.as_ref().map(|sub| Actor { sub: sub.clone(), sid: None, act: None }),
    }
}

/// Whether everything `inner` matches is also matched by `outer`.
fn covers(outer: &str, inner: &str) -> bool {
    match (outer.strip_suffix('*'), inner.strip_suffix('*')) {
        (Some(o), Some(i)) => i.starts_with(o),
        (Some(o), None) => inner.starts_with(o),
        (None, Some(_)) => false,
        (None, None) => outer == inner,
    }
}

/// Starts a top-level session. The caller must be a workload allowed to start
/// sessions for `ask.sub`, and the session can't reach beyond the caller's own
/// grants.
pub fn start(
    policy: &IdentityPolicy,
    sessions: &mut Sessions,
    user: &str,
    ask: &SessionStartAsk,
    sid: String,
    now: u64,
) -> Result<Session, &'static str> {
    let workload = policy.workloads.iter().find(|w| w.user == user).ok_or("not_a_workload")?;
    if !workload.sessions_for.iter().any(|pattern| matches(pattern, &ask.sub)) {
        return Err("sessions_not_granted");
    }
    crate::identity::valid_subject(&ask.sub)?;
    if ask.sub.contains('/') {
        return Err("invalid_subject");
    }
    if let Some(for_sub) = &ask.for_sub {
        crate::identity::valid_subject(for_sub)?;
    }
    let ttl = ask.ttl_seconds.unwrap_or(DEFAULT_SESSION_SECONDS);
    if ttl == 0 || ttl > MAX_SESSION_SECONDS {
        return Err("ttl_out_of_bounds");
    }
    for wanted in &ask.grants {
        let granted = policy
            .grants
            .iter()
            .find(|g| g.sub == workload.sub && g.audience == wanted.audience)
            .ok_or("audience_not_granted")?;
        for scope in &wanted.scopes {
            crate::identity::valid_pattern(scope)?;
            if !granted.scopes.iter().any(|outer| covers(outer, scope)) {
                return Err("scope_not_granted");
            }
        }
    }
    let session = Session {
        sid: sid.clone(),
        sub: ask.sub.clone(),
        parent: None,
        started_by: workload.sub.clone(),
        for_sub: ask.for_sub.clone(),
        grants: ask.grants.clone(),
        created_at: now,
        expires_at: now + ttl,
        revoked_at: None,
    };
    prune(sessions, now);
    sessions.insert(sid, session.clone());
    Ok(session)
}

/// Starts a child of the live session `parent`, reaching one audience with
/// scopes the parent has there. It ends no later than the parent.
pub fn child(
    sessions: &mut Sessions,
    parent: &str,
    name: &str,
    grant: SessionGrant,
    ttl_seconds: Option<u64>,
    sid: String,
    now: u64,
) -> Result<Session, &'static str> {
    if !is_live(sessions, parent, now) {
        return Err("session_not_live");
    }
    // A token acting for the child carries the child, then the parent's chain.
    if 1 + actor_for(sessions, parent).map_or(0, |actor| actor.depth()) > MAX_ACTOR_DEPTH {
        return Err("sessions_too_deep");
    }
    let parent = sessions.get(parent).expect("live sessions exist").clone();
    let name_ok = !name.is_empty()
        && name.len() <= MAX_CHILD_NAME_LEN
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if !name_ok {
        return Err("invalid_name");
    }
    let reach = parent
        .grants
        .iter()
        .find(|g| g.audience == grant.audience)
        .ok_or("audience_not_granted")?;
    for scope in &grant.scopes {
        crate::identity::valid_scope(scope)?;
        if !reach.scopes.iter().any(|outer| matches(outer, scope)) {
            return Err("scope_not_granted");
        }
    }
    let remaining = parent.expires_at - now;
    let ttl = ttl_seconds.unwrap_or(remaining);
    if ttl == 0 {
        return Err("ttl_out_of_bounds");
    }
    let session = Session {
        sid: sid.clone(),
        sub: format!("{}/{name}", parent.sub),
        parent: Some(parent.sid.clone()),
        started_by: parent.started_by.clone(),
        for_sub: None,
        grants: vec![grant],
        created_at: now,
        expires_at: now + ttl.min(remaining),
        revoked_at: None,
    };
    prune(sessions, now);
    sessions.insert(sid, session.clone());
    Ok(session)
}

/// Fills in `request.act` from the session the caller says it acts for, after
/// checking that session is live, is the one named, and reaches what the
/// request asks for.
pub fn bind_actor(sessions: &Sessions, request: &mut IdentityRequest, now: u64) -> Result<(), &'static str> {
    let Some(asked) = request.act.take() else { return Ok(()) };
    let sid = asked.sid.as_deref().ok_or("session_required")?;
    if !is_live(sessions, sid, now) {
        return Err("session_not_live");
    }
    let session = &sessions[sid];
    if session.sub != asked.sub {
        return Err("session_not_live");
    }
    let reach = session
        .grants
        .iter()
        .find(|g| g.audience == request.aud)
        .ok_or("audience_not_in_session")?;
    if !request.scopes.iter().all(|scope| reach.scopes.iter().any(|outer| matches(outer, scope))) {
        return Err("scope_not_in_session");
    }
    request.act = actor_for(sessions, sid);
    Ok(())
}

/// Marks `sid` revoked; everything under it stops being live with it.
pub fn revoke(sessions: &mut Sessions, sid: &str, now: u64) -> bool {
    match sessions.get_mut(sid) {
        Some(session) if session.revoked_at.is_none() => {
            session.revoked_at = Some(now);
            true
        }
        Some(_) => true,
        None => false,
    }
}

/// `sid` and every session under it, parents before children.
pub fn tree(sessions: &Sessions, sid: &str) -> Vec<Session> {
    let mut out: Vec<Session> = sessions.get(sid).into_iter().cloned().collect();
    let mut at = 0;
    while at < out.len() {
        let parent = out[at].sid.clone();
        out.extend(sessions.values().filter(|s| s.parent.as_deref() == Some(&parent)).cloned());
        at += 1;
    }
    out
}

fn prune(sessions: &mut Sessions, now: u64) {
    sessions.retain(|_, s| s.expires_at.saturating_add(KEEP_ENDED_SECONDS) > now);
}

#[cfg(test)]
mod tests {
    use super::*;
    use harar_client::oidc::{Grant, Workload};

    const SIMIEN: &str = "https://api.simien.dev";
    const GILD: &str = "https://gild.gg";
    const NOW: u64 = 1_800_000_000;

    fn policy() -> IdentityPolicy {
        IdentityPolicy {
            workloads: vec![Workload { sub: "svc:gild@demon".into(), user: "gild".into(), sessions_for: vec!["agent:*".into()], runs_for: vec![] }],
            grants: vec![
                Grant { sub: "svc:gild@demon".into(), audience: SIMIEN.into(), scopes: vec!["deploy:*".into()], may_act_for: vec!["agent:*".into()] },
                Grant { sub: "svc:gild@demon".into(), audience: GILD.into(), scopes: vec!["repo:*".into()], may_act_for: vec!["agent:*".into()] },
            ],
        }
    }

    fn ava_ask() -> SessionStartAsk {
        SessionStartAsk {
            sub: "agent:ava".into(),
            for_sub: Some("user:sami".into()),
            ttl_seconds: None,
            grants: vec![
                SessionGrant { audience: SIMIEN.into(), scopes: vec!["deploy:staging".into()] },
                SessionGrant { audience: GILD.into(), scopes: vec!["repo:*".into()] },
            ],
        }
    }

    fn started() -> Sessions {
        let mut sessions = Sessions::new();
        start(&policy(), &mut sessions, "gild", &ava_ask(), "s_ava".into(), NOW).unwrap();
        sessions
    }

    fn token_request(scopes: &[&str], aud: &str) -> IdentityRequest {
        IdentityRequest {
            sub: "svc:gild@demon".into(),
            aud: aud.into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            ttl_seconds: 300,
            act: Some(Actor { sub: "agent:ava".into(), sid: Some("s_ava".into()), act: None }),
            extra: Default::default(),
        }
    }

    #[test]
    fn acting_for_a_session_gives_the_whole_chain() {
        let sessions = started();
        let mut request = token_request(&["deploy:staging"], SIMIEN);
        bind_actor(&sessions, &mut request, NOW + 1).unwrap();
        assert_eq!(request.act.unwrap().chain(), ["agent:ava", "user:sami"]);
    }

    #[test]
    fn acting_needs_a_live_matching_session_that_reaches_the_request() {
        let mut sessions = started();
        let refuse = |sessions: &Sessions, mut request: IdentityRequest| bind_actor(sessions, &mut request, NOW + 1).unwrap_err();

        let mut no_sid = token_request(&[], SIMIEN);
        no_sid.act.as_mut().unwrap().sid = None;
        assert_eq!(refuse(&sessions, no_sid), "session_required");
        let mut someone_else = token_request(&[], SIMIEN);
        someone_else.act.as_mut().unwrap().sub = "agent:mallory".into();
        assert_eq!(refuse(&sessions, someone_else), "session_not_live");
        assert_eq!(refuse(&sessions, token_request(&["deploy:production"], SIMIEN)), "scope_not_in_session");
        assert_eq!(refuse(&sessions, token_request(&[], "https://other.test")), "audience_not_in_session");

        let mut late = token_request(&[], SIMIEN);
        assert_eq!(bind_actor(&sessions, &mut late, NOW + DEFAULT_SESSION_SECONDS), Err("session_not_live"));
        revoke(&mut sessions, "s_ava", NOW + 2);
        assert_eq!(refuse(&sessions, token_request(&[], SIMIEN)), "session_not_live");
    }

    #[test]
    fn sessions_start_only_within_the_starters_own_grants() {
        let mut sessions = Sessions::new();
        let try_start = |sessions: &mut Sessions, user: &str, ask: SessionStartAsk| start(&policy(), sessions, user, &ask, "s_x".into(), NOW);
        assert_eq!(try_start(&mut sessions, "mallory", ava_ask()), Err("not_a_workload"));
        assert_eq!(try_start(&mut sessions, "gild", SessionStartAsk { sub: "svc:db".into(), ..ava_ask() }), Err("sessions_not_granted"));
        assert_eq!(try_start(&mut sessions, "gild", SessionStartAsk { sub: "agent:a/b".into(), ..ava_ask() }), Err("invalid_subject"));
        let wider = SessionStartAsk { grants: vec![SessionGrant { audience: SIMIEN.into(), scopes: vec!["admin:*".into()] }], ..ava_ask() };
        assert_eq!(try_start(&mut sessions, "gild", wider), Err("scope_not_granted"));
        let all = SessionStartAsk { grants: vec![SessionGrant { audience: SIMIEN.into(), scopes: vec!["*".into()] }], ..ava_ask() };
        assert_eq!(try_start(&mut sessions, "gild", all), Err("scope_not_granted"));
        let elsewhere = SessionStartAsk { grants: vec![SessionGrant { audience: "https://x.test".into(), scopes: vec![] }], ..ava_ask() };
        assert_eq!(try_start(&mut sessions, "gild", elsewhere), Err("audience_not_granted"));
        let long = SessionStartAsk { ttl_seconds: Some(MAX_SESSION_SECONDS + 1), ..ava_ask() };
        assert_eq!(try_start(&mut sessions, "gild", long), Err("ttl_out_of_bounds"));
        assert!(sessions.is_empty());
    }

    #[test]
    fn children_are_narrower_and_die_with_their_parent() {
        let mut sessions = started();
        let review = SessionGrant { audience: GILD.into(), scopes: vec!["repo:read".into()] };
        let child = child(&mut sessions, "s_ava", "reviewer", review.clone(), Some(1800), "s_rev".into(), NOW + 10).unwrap();
        assert_eq!(child.sub, "agent:ava/reviewer");
        assert_eq!(child.started_by, "svc:gild@demon");
        assert_eq!(actor_for(&sessions, "s_rev").unwrap().chain(), ["agent:ava/reviewer", "agent:ava", "user:sami"]);

        let grandchild = SessionGrant { audience: GILD.into(), scopes: vec!["repo:read".into()] };
        super::child(&mut sessions, "s_rev", "linter", grandchild, None, "s_lint".into(), NOW + 20).unwrap();
        assert_eq!(sessions["s_lint"].expires_at, sessions["s_rev"].expires_at, "a child never outlives its parent");

        let wider = SessionGrant { audience: GILD.into(), scopes: vec!["repo:write".into()] };
        assert_eq!(super::child(&mut sessions, "s_rev", "x", wider, None, "s_w".into(), NOW + 30), Err("scope_not_granted"));
        let other_aud = SessionGrant { audience: SIMIEN.into(), scopes: vec![] };
        assert_eq!(super::child(&mut sessions, "s_rev", "x", other_aud, None, "s_o".into(), NOW + 30), Err("audience_not_granted"));
        assert_eq!(super::child(&mut sessions, "s_rev", "a/b", review.clone(), None, "s_n".into(), NOW + 30), Err("invalid_name"));

        let long = super::child(&mut sessions, "s_ava", "long", review.clone(), Some(MAX_SESSION_SECONDS), "s_long".into(), NOW + 40).unwrap();
        assert_eq!(long.expires_at, sessions["s_ava"].expires_at);

        assert!(revoke(&mut sessions, "s_ava", NOW + 50));
        for sid in ["s_ava", "s_rev", "s_lint", "s_long"] {
            assert!(!is_live(&sessions, sid, NOW + 51), "{sid} outlived a revoked ancestor");
        }
        assert_eq!(super::child(&mut sessions, "s_rev", "late", review, None, "s_late".into(), NOW + 52), Err("session_not_live"));
        let tree: Vec<_> = tree(&sessions, "s_ava").into_iter().map(|s| s.sid).collect();
        assert_eq!(tree, ["s_ava", "s_long", "s_rev", "s_lint"]);
    }

    #[test]
    fn chains_stop_at_the_depth_limit() {
        let mut sessions = started();
        let grant = SessionGrant { audience: GILD.into(), scopes: vec![] };
        let mut parent = "s_ava".to_string();
        // s_ava's chain is ava + sami; each child adds one.
        for depth in 1..MAX_ACTOR_DEPTH - 1 {
            let sid = format!("s_{depth}");
            child(&mut sessions, &parent, "c", grant.clone(), None, sid.clone(), NOW).unwrap();
            parent = sid;
        }
        assert_eq!(child(&mut sessions, &parent, "c", grant, None, "s_deep".into(), NOW), Err("sessions_too_deep"));
        assert_eq!(actor_for(&sessions, &parent).unwrap().depth(), MAX_ACTOR_DEPTH);
    }

    #[test]
    fn ended_sessions_are_pruned_a_day_later() {
        let mut sessions = started();
        let later = NOW + DEFAULT_SESSION_SECONDS + KEEP_ENDED_SECONDS;
        start(&policy(), &mut sessions, "gild", &ava_ask(), "s_new".into(), later).unwrap();
        assert!(!sessions.contains_key("s_ava"));
        assert!(sessions.contains_key("s_new"));
    }

    #[test]
    fn covers_is_containment() {
        assert!(covers("repo:*", "repo:read"));
        assert!(covers("repo:*", "repo:x*"));
        assert!(covers("*", "anything:*"));
        assert!(!covers("repo:read", "repo:*"));
        assert!(!covers("repo:r*", "repo:*"));
        assert!(!covers("deploy:*", "admin:*"));
    }
}
