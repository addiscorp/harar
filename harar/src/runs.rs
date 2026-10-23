//! CI runs (scenario S3): a gild host registers a run's facts, and env rules
//! decide whether that run gets an environment's build secrets or a token to
//! deploy with. Runs an agent started can be made to wait for a person.
//!
//! Stored as one vault entry, like the identity rules and sessions.

use crate::identity::{matches, valid_pattern, valid_subject};
use harar_client::oidc::{Actor, IdentityPolicy, IdentityRequest, MAX_TTL_SECONDS};
use harar_client::runs::{Approval, EnvRule, RUN_CLAIM, Run, RunRegisterAsk, RunsState};
use std::collections::{BTreeMap, HashMap};

pub const RUNS_KEY: &str = "harar:runs";
pub const DEFAULT_RUN_SECONDS: u64 = 3600;
pub const MAX_RUN_SECONDS: u64 = 6 * 3600;
const KEEP_ENDED_SECONDS: u64 = 7 * 24 * 3600;

pub fn load(keys: &HashMap<String, String>) -> Result<RunsState, &'static str> {
    match keys.get(RUNS_KEY) {
        None => Ok(RunsState::default()),
        Some(text) => serde_json::from_str(text).map_err(|_| "runs_corrupt"),
    }
}

pub fn store(state: &RunsState) -> String {
    serde_json::to_string(state).expect("runs serialize")
}

fn valid_env_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn plain(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/'))
}

/// Adds an env rule, or replaces the one with the same name.
pub fn set_rule(state: &mut RunsState, rule: EnvRule) -> Result<(), &'static str> {
    if !valid_env_name(&rule.name) {
        return Err("invalid_env");
    }
    for pattern in [&rule.repo, &rule.git_ref, &rule.workflow].into_iter().chain(&rule.secrets) {
        valid_pattern(pattern)?;
    }
    if rule.secrets.iter().any(|p| p.starts_with("harar:") || p == "*") {
        return Err("invalid_pattern");
    }
    if rule.audiences.iter().any(|a| a.is_empty() || a.contains(char::is_whitespace)) {
        return Err("invalid_audience");
    }
    state.rules.retain(|r| r.name != rule.name);
    state.rules.push(rule);
    state.rules.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(())
}

pub fn remove_rule(state: &mut RunsState, name: &str) -> bool {
    let before = state.rules.len();
    state.rules.retain(|r| r.name != name);
    before != state.rules.len()
}

/// Registers a run. The caller must be a workload allowed to register runs
/// for the repo; it vouches for every fact.
pub fn register(
    policy: &IdentityPolicy,
    state: &mut RunsState,
    user: &str,
    ask: &RunRegisterAsk,
    id: String,
    now: u64,
) -> Result<Run, &'static str> {
    let workload = policy.workloads.iter().find(|w| w.user == user).ok_or("not_a_workload")?;
    let facts = &ask.facts;
    if !workload.runs_for.iter().any(|pattern| matches(pattern, &facts.repo)) {
        return Err("runs_not_granted");
    }
    let sha_ok = (7..=64).contains(&facts.sha.len()) && facts.sha.bytes().all(|b| b.is_ascii_hexdigit());
    let ok = plain(&facts.repo, 200)
        && facts.repo.contains('/')
        && sha_ok
        && facts.git_ref.starts_with("refs/")
        && plain(&facts.git_ref, 250)
        && plain(&facts.workflow, 200)
        && valid_env_name(&facts.env);
    if !ok {
        return Err("invalid_run_facts");
    }
    valid_subject(&facts.actor)?;
    if let Some(for_sub) = &facts.for_sub {
        valid_subject(for_sub)?;
    }
    let ttl = ask.ttl_seconds.unwrap_or(DEFAULT_RUN_SECONDS);
    if ttl == 0 || ttl > MAX_RUN_SECONDS {
        return Err("ttl_out_of_bounds");
    }
    let run = Run {
        id: id.clone(),
        facts: facts.clone(),
        registered_by: workload.sub.clone(),
        created_at: now,
        expires_at: now + ttl,
        finished_at: None,
        approval: None,
    };
    state.runs.retain(|_, r| r.expires_at.saturating_add(KEEP_ENDED_SECONDS) > now);
    state.runs.insert(id, run.clone());
    Ok(run)
}

fn live_run<'a>(state: &'a RunsState, id: &str, now: u64) -> Result<&'a Run, &'static str> {
    let run = state.runs.get(id).ok_or("run_not_live")?;
    if run.finished_at.is_some() || run.expires_at <= now {
        return Err("run_not_live");
    }
    Ok(run)
}

/// The env rule that lets this run use its environment.
fn rule_for<'a>(state: &'a RunsState, run: &Run) -> Result<&'a EnvRule, &'static str> {
    let facts = &run.facts;
    state
        .rules
        .iter()
        .find(|r| {
            r.name == facts.env
                && matches(&r.repo, &facts.repo)
                && matches(&r.git_ref, &facts.git_ref)
                && matches(&r.workflow, &facts.workflow)
        })
        .ok_or("env_rule_refuses")
}

/// Whether a person must say yes first, and whether they have. Asking marks
/// the run pending so it shows up in `harar approvals list`.
fn approved(state: &mut RunsState, id: &str, rule_wants_person: bool) -> Result<(), &'static str> {
    let run = state.runs.get_mut(id).expect("checked live");
    if !rule_wants_person || !run.facts.actor.starts_with("agent:") {
        return Ok(());
    }
    match run.approval {
        Some(Approval::Approved) => Ok(()),
        Some(Approval::Denied) => Err("run_denied"),
        Some(Approval::Pending) => Err("approval_pending"),
        None => {
            run.approval = Some(Approval::Pending);
            Err("approval_pending")
        }
    }
}

/// The build secrets run `id` gets for `env`: every vault key its env rule
/// names, by full key. `harar run` names them by their last segment.
///
/// A run that needs a person is marked pending here, so the caller saves the
/// state whatever this returns.
pub fn secrets(
    state: &mut RunsState,
    keys: &HashMap<String, String>,
    id: &str,
    env: &str,
    now: u64,
) -> Result<BTreeMap<String, String>, &'static str> {
    let run = live_run(state, id, now)?.clone();
    if run.facts.env != env {
        return Err("wrong_env");
    }
    let rule = rule_for(state, &run)?.clone();
    approved(state, id, rule.approve_when_agent)?;
    Ok(keys
        .iter()
        .filter(|(key, _)| !key.starts_with("harar:") && rule.secrets.iter().any(|pattern| matches(pattern, key)))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect())
}

/// An identity token for run `id` to present to `audience` (say, simien's
/// trusted publishing): the run's facts as claims, for no longer than the run.
pub fn token(state: &mut RunsState, id: &str, audience: &str, now: u64) -> Result<IdentityRequest, &'static str> {
    let run = live_run(state, id, now)?.clone();
    let rule = rule_for(state, &run)?.clone();
    if !rule.audiences.iter().any(|a| a == audience) {
        return Err("audience_not_granted");
    }
    approved(state, id, rule.approve_when_agent)?;
    let mut request = run_identity(&run, now);
    request.aud = audience.to_string();
    Ok(request)
}

/// The claims every token for this run carries. The audience is filled in by
/// the caller.
pub fn run_identity(run: &Run, now: u64) -> IdentityRequest {
    let facts = &run.facts;
    let extra = BTreeMap::from([
        ("repo".to_string(), facts.repo.clone().into()),
        ("sha".to_string(), facts.sha.clone().into()),
        ("ref".to_string(), facts.git_ref.clone().into()),
        ("workflow".to_string(), facts.workflow.clone().into()),
        ("env".to_string(), facts.env.clone().into()),
        ("actor".to_string(), facts.actor.clone().into()),
        (RUN_CLAIM.to_string(), run.id.clone().into()),
    ]);
    let for_actor = facts.for_sub.as_ref().map(|sub| Box::new(Actor { sub: sub.clone(), sid: None, act: None }));
    IdentityRequest {
        sub: facts.subject(),
        aud: String::new(),
        scopes: vec![],
        ttl_seconds: (run.expires_at - now).min(MAX_TTL_SECONDS),
        act: Some(Actor { sub: facts.actor.clone(), sid: None, act: for_actor }),
        extra,
    }
}

pub fn decide(state: &mut RunsState, id: &str, approve: bool) -> Result<Run, &'static str> {
    let run = state.runs.get_mut(id).ok_or("not_found")?;
    if run.approval != Some(Approval::Pending) {
        return Err("not_pending");
    }
    run.approval = Some(if approve { Approval::Approved } else { Approval::Denied });
    Ok(run.clone())
}

pub fn finish(state: &mut RunsState, id: &str, now: u64) -> Result<Run, &'static str> {
    let run = state.runs.get_mut(id).ok_or("not_found")?;
    run.finished_at.get_or_insert(now);
    Ok(run.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use harar_client::oidc::Workload;
    use harar_client::runs::RunFacts;

    const NOW: u64 = 1_800_000_000;

    fn policy() -> IdentityPolicy {
        IdentityPolicy {
            workloads: vec![Workload {
                sub: "svc:gild@demon".into(),
                user: "gild".into(),
                sessions_for: vec![],
                runs_for: vec!["addiscorp/*".into()],
            }],
            grants: vec![],
        }
    }

    fn production() -> EnvRule {
        EnvRule {
            name: "production".into(),
            repo: "addiscorp/site".into(),
            git_ref: "refs/heads/main".into(),
            workflow: "deploy.yml".into(),
            secrets: vec!["prod/site/*".into()],
            audiences: vec!["https://api.simien.dev".into()],
            approve_when_agent: true,
        }
    }

    fn facts(actor: &str) -> RunFacts {
        RunFacts {
            repo: "addiscorp/site".into(),
            sha: "4e1a9c0".into(),
            git_ref: "refs/heads/main".into(),
            workflow: "deploy.yml".into(),
            env: "production".into(),
            actor: actor.into(),
            for_sub: Some("user:sami".into()),
        }
    }

    fn keys() -> HashMap<String, String> {
        HashMap::from([
            ("prod/site/DATABASE_URL".to_string(), "postgres://prod".to_string()),
            ("prod/site/STRIPE_KEY".to_string(), "sk_live".to_string()),
            ("prod/other/SECRET".to_string(), "not yours".to_string()),
            ("dev/site/DATABASE_URL".to_string(), "postgres://dev".to_string()),
        ])
    }

    fn registered(actor: &str) -> RunsState {
        let mut state = RunsState::default();
        set_rule(&mut state, production()).unwrap();
        let ask = RunRegisterAsk { facts: facts(actor), ttl_seconds: None };
        register(&policy(), &mut state, "gild", &ask, "run_88".into(), NOW).unwrap();
        state
    }

    #[test]
    fn a_matching_run_gets_only_its_environments_secrets() {
        let mut state = registered("user:sami");
        let got = secrets(&mut state, &keys(), "run_88", "production", NOW + 1).unwrap();
        assert_eq!(
            got,
            BTreeMap::from([
                ("prod/site/DATABASE_URL".to_string(), "postgres://prod".to_string()),
                ("prod/site/STRIPE_KEY".to_string(), "sk_live".to_string()),
            ])
        );
        assert_eq!(secrets(&mut state, &keys(), "run_88", "staging", NOW + 1), Err("wrong_env"));
    }

    #[test]
    fn runs_from_elsewhere_are_refused_by_the_rule() {
        for (field, value) in [("repo", "addiscorp/other"), ("ref", "refs/heads/feature"), ("workflow", "evil.yml")] {
            let mut state = RunsState::default();
            set_rule(&mut state, production()).unwrap();
            let mut facts = facts("user:sami");
            match field {
                "repo" => facts.repo = value.into(),
                "ref" => facts.git_ref = value.into(),
                _ => facts.workflow = value.into(),
            }
            register(&policy(), &mut state, "gild", &RunRegisterAsk { facts, ttl_seconds: None }, "r".into(), NOW).unwrap();
            assert_eq!(secrets(&mut state, &keys(), "r", "production", NOW), Err("env_rule_refuses"), "{field}");
        }
    }

    #[test]
    fn an_agents_run_waits_for_a_person() {
        let mut state = registered("agent:ava");
        assert_eq!(secrets(&mut state, &keys(), "run_88", "production", NOW + 1), Err("approval_pending"));
        assert_eq!(state.runs["run_88"].approval, Some(Approval::Pending), "asking shows it in the approvals list");
        assert_eq!(token(&mut state, "run_88", "https://api.simien.dev", NOW + 1), Err("approval_pending"));
        decide(&mut state, "run_88", true).unwrap();
        assert!(secrets(&mut state, &keys(), "run_88", "production", NOW + 2).is_ok());
        assert_eq!(decide(&mut state, "run_88", false), Err("not_pending"));

        let mut denied = registered("agent:ava");
        let _ = secrets(&mut denied, &keys(), "run_88", "production", NOW);
        decide(&mut denied, "run_88", false).unwrap();
        assert_eq!(secrets(&mut denied, &keys(), "run_88", "production", NOW), Err("run_denied"));
    }

    #[test]
    fn deploy_tokens_carry_the_run_and_only_go_to_named_audiences() {
        let mut state = registered("user:sami");
        let request = token(&mut state, "run_88", "https://api.simien.dev", NOW + 10).unwrap();
        assert_eq!(request.sub, "run:addiscorp/site:deploy.yml:production");
        assert_eq!(request.extra["sha"], "4e1a9c0");
        assert_eq!(request.extra["run"], "run_88");
        assert_eq!(request.extra["actor"], "user:sami");
        assert_eq!(request.ttl_seconds, DEFAULT_RUN_SECONDS - 10);
        assert_eq!(token(&mut state, "run_88", "https://gild.gg", NOW), Err("audience_not_granted"));
    }

    #[test]
    fn finished_or_expired_runs_get_nothing() {
        let mut state = registered("user:sami");
        finish(&mut state, "run_88", NOW + 5).unwrap();
        assert_eq!(secrets(&mut state, &keys(), "run_88", "production", NOW + 6), Err("run_not_live"));
        let mut state = registered("user:sami");
        assert_eq!(secrets(&mut state, &keys(), "run_88", "production", NOW + DEFAULT_RUN_SECONDS), Err("run_not_live"));
    }

    #[test]
    fn registering_needs_the_repo_and_sane_facts() {
        let mut state = RunsState::default();
        let ask = |facts| RunRegisterAsk { facts, ttl_seconds: None };
        let other = RunFacts { repo: "someone/else".into(), ..facts("user:sami") };
        assert_eq!(register(&policy(), &mut state, "gild", &ask(other), "r".into(), NOW), Err("runs_not_granted"));
        assert_eq!(register(&policy(), &mut state, "mallory", &ask(facts("user:sami")), "r".into(), NOW), Err("not_a_workload"));
        for bad in [
            RunFacts { sha: "xyz".into(), ..facts("user:sami") },
            RunFacts { git_ref: "main".into(), ..facts("user:sami") },
            RunFacts { env: "Prod Env".into(), ..facts("user:sami") },
        ] {
            assert_eq!(register(&policy(), &mut state, "gild", &ask(bad), "r".into(), NOW), Err("invalid_run_facts"));
        }
        let long = RunRegisterAsk { facts: facts("user:sami"), ttl_seconds: Some(MAX_RUN_SECONDS + 1) };
        assert_eq!(register(&policy(), &mut state, "gild", &long, "r".into(), NOW), Err("ttl_out_of_bounds"));
    }

    #[test]
    fn rules_cannot_hand_out_harars_own_entries_or_everything() {
        let mut state = RunsState::default();
        for secrets in [vec!["harar:*".to_string()], vec!["*".to_string()]] {
            assert_eq!(set_rule(&mut state, EnvRule { secrets, ..production() }), Err("invalid_pattern"));
        }
        let mut keys = keys();
        keys.insert("harar:identity".into(), "{}".into());
        let rule = EnvRule { secrets: vec!["prod/*".into()], ..production() };
        set_rule(&mut state, rule).unwrap();
        let ask = RunRegisterAsk { facts: facts("user:sami"), ttl_seconds: None };
        register(&policy(), &mut state, "gild", &ask, "r".into(), NOW).unwrap();
        let got = secrets(&mut state, &keys, "r", "production", NOW).unwrap();
        assert!(got.contains_key("prod/other/SECRET"));
        assert!(!got.contains_key("harar:identity"), "harar's own entries never leave");
    }
}
