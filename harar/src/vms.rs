//! The issuer's side of VM identity: which CID on which host is which VM, and
//! what a VM may get. Only the workload that registered a VM (the host's
//! vsock service) may ask on its behalf.

use crate::sessions::{self, Sessions};
use harar_client::oidc::{DEFAULT_TTL_SECONDS, IdentityRequest, MAX_TTL_SECONDS, SID_CLAIM, TokenAsk};
use harar_client::runs::RunsState;
use harar_client::vms::{Vm, VmFor, VmsState};
use std::collections::{BTreeMap, HashMap};

pub const VMS_KEY: &str = "harar:vms";

pub fn load(keys: &HashMap<String, String>) -> Result<VmsState, &'static str> {
    match keys.get(VMS_KEY) {
        None => Ok(VmsState::default()),
        Some(text) => serde_json::from_str(text).map_err(|_| "vms_corrupt"),
    }
}

pub fn store(state: &VmsState) -> String {
    serde_json::to_string(state).expect("vms serialize")
}

fn slot(host_workload: &str, cid: u32) -> String {
    format!("{host_workload}/{cid}")
}

/// Registers (or re-registers, when a CID is reused) a VM. The caller has
/// already been checked to manage the session or run it runs for.
pub fn register(state: &mut VmsState, host_workload: &str, cid: u32, name: &str, runs_for: VmFor, now: u64) -> Result<Vm, &'static str> {
    // 0 is the hypervisor and 2 the host, never a guest. 1 is this machine's
    // loopback, which the tests use.
    if cid == 0 || cid == 2 || cid == u32::MAX {
        return Err("invalid_cid");
    }
    let name_ok = !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if !name_ok {
        return Err("invalid_name");
    }
    let vm = Vm { id: format!("vm:{name}"), cid, host_workload: host_workload.to_string(), runs_for, created_at: now };
    state.vms.insert(slot(host_workload, cid), vm.clone());
    Ok(vm)
}

pub fn forget(state: &mut VmsState, host_workload: &str, cid: u32) -> bool {
    state.vms.remove(&slot(host_workload, cid)).is_some()
}

pub fn find<'a>(state: &'a VmsState, host_workload: &str, cid: u32) -> Result<&'a Vm, &'static str> {
    state.vms.get(&slot(host_workload, cid)).ok_or("unknown_vm")
}

/// A token for a session VM: the VM as subject, acting for the session's
/// chain, and only within what the session may reach.
pub fn session_token(sessions: &Sessions, vm: &Vm, ask: &TokenAsk, now: u64) -> Result<IdentityRequest, &'static str> {
    let VmFor::Session(sid) = &vm.runs_for else { return Err("not_a_session_vm") };
    if !sessions::is_live(sessions, sid, now) {
        return Err("session_not_live");
    }
    let session = &sessions[sid];
    let reach = session.grants.iter().find(|g| g.audience == ask.audience).ok_or("audience_not_in_session")?;
    for scope in &ask.scopes {
        crate::identity::valid_scope(scope)?;
        if !reach.scopes.iter().any(|outer| crate::identity::matches(outer, scope)) {
            return Err("scope_not_in_session");
        }
    }
    let ttl = ask.ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
    if ttl == 0 || ttl > MAX_TTL_SECONDS {
        return Err("ttl_out_of_bounds");
    }
    Ok(IdentityRequest {
        sub: vm.id.clone(),
        aud: ask.audience.clone(),
        scopes: ask.scopes.clone(),
        ttl_seconds: ttl.min(session.expires_at - now),
        act: sessions::actor_for(sessions, sid),
        extra: BTreeMap::from([(SID_CLAIM.to_string(), sid.clone().into())]),
    })
}

/// A deploy token for a run VM: the run's own token, plus which VM asked.
pub fn run_token(runs: &mut RunsState, vm: &Vm, ask: &TokenAsk, now: u64) -> Result<IdentityRequest, &'static str> {
    let VmFor::Run(run) = &vm.runs_for else { return Err("not_a_run_vm") };
    let mut request = crate::runs::token(runs, run, &ask.audience, now)?;
    request.extra.insert("vm".to_string(), vm.id.clone().into());
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use harar_client::oidc::{Grant, IdentityPolicy, SessionGrant, SessionStartAsk, Workload};

    const NOW: u64 = 1_800_000_000;
    const GILD: &str = "https://gild.gg";

    fn sessions() -> Sessions {
        let policy = IdentityPolicy {
            workloads: vec![Workload { sub: "svc:gild".into(), user: "gild".into(), sessions_for: vec!["agent:*".into()], runs_for: vec![] }],
            grants: vec![Grant { sub: "svc:gild".into(), audience: GILD.into(), scopes: vec!["repo:*".into()], may_act_for: vec![], hardware_only: false }],
        };
        let mut all = Sessions::new();
        let ask = SessionStartAsk {
            sub: "agent:ava".into(),
            for_sub: Some("user:sami".into()),
            ttl_seconds: Some(3600),
            grants: vec![SessionGrant { audience: GILD.into(), scopes: vec!["repo:read".into()] }],
        };
        sessions::start(&policy, &mut all, "gild", &ask, "s_ava".into(), NOW).unwrap();
        all
    }

    fn ask(scopes: &[&str]) -> TokenAsk {
        TokenAsk { audience: GILD.into(), scopes: scopes.iter().map(|s| s.to_string()).collect(), ttl_seconds: None, act: None, alg: None }
    }

    #[test]
    fn a_session_vm_speaks_as_itself_for_the_session() {
        let all = sessions();
        let mut state = VmsState::default();
        let vm = register(&mut state, "svc:gild", 7, "r88", VmFor::Session("s_ava".into()), NOW).unwrap();
        let request = session_token(&all, &vm, &ask(&["repo:read"]), NOW + 1).unwrap();
        assert_eq!(request.sub, "vm:r88");
        assert_eq!(request.act.unwrap().chain(), ["agent:ava", "user:sami"]);
        assert_eq!(request.extra[SID_CLAIM], "s_ava");
        assert_eq!(session_token(&all, &vm, &ask(&["repo:write"]), NOW), Err("scope_not_in_session"));
    }

    #[test]
    fn cids_belong_to_the_host_that_registered_them() {
        let mut state = VmsState::default();
        register(&mut state, "svc:gild@demon", 7, "a", VmFor::Session("s".into()), NOW).unwrap();
        register(&mut state, "svc:gild@bugsy", 7, "b", VmFor::Session("s".into()), NOW).unwrap();
        assert_eq!(find(&state, "svc:gild@demon", 7).unwrap().id, "vm:a");
        assert_eq!(find(&state, "svc:gild@bugsy", 7).unwrap().id, "vm:b");
        assert_eq!(find(&state, "svc:other", 7), Err("unknown_vm"));
        // A reused CID is a new VM.
        register(&mut state, "svc:gild@demon", 7, "c", VmFor::Run("run_1".into()), NOW).unwrap();
        assert_eq!(find(&state, "svc:gild@demon", 7).unwrap().id, "vm:c");
        assert!(forget(&mut state, "svc:gild@demon", 7));
        assert_eq!(find(&state, "svc:gild@demon", 7), Err("unknown_vm"));
        assert_eq!(register(&mut state, "svc:gild", 2, "host", VmFor::Run("r".into()), NOW), Err("invalid_cid"));
    }

    #[test]
    fn a_revoked_session_ends_its_vms_tokens() {
        let mut all = sessions();
        let mut state = VmsState::default();
        let vm = register(&mut state, "svc:gild", 7, "r88", VmFor::Session("s_ava".into()), NOW).unwrap();
        sessions::revoke(&mut all, "s_ava", NOW + 1);
        assert_eq!(session_token(&all, &vm, &ask(&[]), NOW + 2), Err("session_not_live"));
    }
}
