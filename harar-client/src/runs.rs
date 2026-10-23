//! CI runs and the environments they may build for. A gild host registers
//! each run's facts; an env rule says which runs get an environment's secrets
//! and which audiences they may deploy to.

/// Which runs may use the environment `name`. Patterns are exact or a prefix
/// ending in `*`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnvRule {
    pub name: String,
    pub repo: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub workflow: String,
    /// Vault keys the build gets, such as `prod/site/*`.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// Services the run may get identity tokens for, such as simien.
    #[serde(default)]
    pub audiences: Vec<String>,
    /// Runs started by an agent wait for a person to approve them.
    #[serde(default)]
    pub approve_when_agent: bool,
}

/// What the gild host knows about a run, and vouches for.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RunFacts {
    pub repo: String,
    pub sha: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub workflow: String,
    pub env: String,
    /// Who started it, such as `agent:ava` or `user:sami`.
    pub actor: String,
    /// Whom the actor works for, when the actor is an agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub for_sub: Option<String>,
}

impl RunFacts {
    /// `run:<repo>:<workflow>:<env>`, the subject of a run's tokens.
    pub fn subject(&self) -> String {
        format!("run:{}:{}:{}", self.repo, self.workflow, self.env)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Approval {
    Pending,
    Approved,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Run {
    pub id: String,
    pub facts: RunFacts,
    pub registered_by: String,
    pub created_at: u64,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<u64>,
    /// Set once the run first asks for something that needs a person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<Approval>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RunsState {
    #[serde(default)]
    pub rules: Vec<EnvRule>,
    #[serde(default)]
    pub runs: std::collections::BTreeMap<String, Run>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RunRegisterAsk {
    pub facts: RunFacts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
}

/// The claim carrying a run's id in its tokens.
pub const RUN_CLAIM: &str = "run";
