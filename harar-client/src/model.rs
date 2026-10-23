//! The identity model from `docs/architecture.md`: reverse-DNS names, zones,
//! profiles, roles, bindings, and the one request rule every decision uses.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

const MAX_NAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;
/// How deep zones may nest (machine → VM → container → process, with room).
const MAX_ZONE_DEPTH: usize = 8;

/// The kind segment of a name. These words are reserved: no org label may be one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Human,
    Agent,
    Service,
    Broker,
    Zone,
    Role,
    Profile,
}

impl Kind {
    const ALL: [Kind; 7] = [Kind::Human, Kind::Agent, Kind::Service, Kind::Broker, Kind::Zone, Kind::Role, Kind::Profile];

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Human => "human",
            Kind::Agent => "agent",
            Kind::Service => "service",
            Kind::Broker => "broker",
            Kind::Zone => "zone",
            Kind::Role => "role",
            Kind::Profile => "profile",
        }
    }

    fn parse(label: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|kind| kind.as_str() == label)
    }

    /// Kinds that can be responsible for a request.
    pub fn is_actor(self) -> bool {
        matches!(self, Kind::Human | Kind::Agent | Kind::Service | Kind::Broker)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameError {
    TooLong,
    BadLabel(String),
    NoKind,
    OrgTooShort,
    KindInOrg(String),
    LocalMissing,
    LocalTooLong,
    WrongKind { expected: Kind, found: Kind },
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameError::TooLong => write!(f, "a name is at most {MAX_NAME_LEN} characters"),
            NameError::BadLabel(label) => write!(f, "{label:?} is not a label: use a-z, 0-9 and -, 1-63 characters, no - at either end"),
            NameError::NoKind => write!(f, "a name needs a kind: human, agent, service, broker, zone, role or profile"),
            NameError::OrgTooShort => write!(f, "an org is at least two labels, its domain reversed (gg.addis)"),
            NameError::KindInOrg(label) => write!(f, "{label:?} is a kind and can't be part of an org"),
            NameError::LocalMissing => write!(f, "a name ends with exactly one label after its kind"),
            NameError::LocalTooLong => write!(f, "a name ends with exactly one label after its kind"),
            NameError::WrongKind { expected, found } => {
                write!(f, "expected a {} name, got a {} name", expected.as_str(), found.as_str())
            }
        }
    }
}

impl std::error::Error for NameError {}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL_LEN
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// An org: its domain reversed, two or more labels (`gg.addis`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Org(String);

impl Org {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn from_labels(labels: &[&str]) -> Result<Org, NameError> {
        if labels.len() < 2 {
            return Err(NameError::OrgTooShort);
        }
        for label in labels {
            if Kind::parse(label).is_some() {
                return Err(NameError::KindInOrg(label.to_string()));
            }
            if !valid_label(label) {
                return Err(NameError::BadLabel(label.to_string()));
            }
        }
        Ok(Org(labels.join(".")))
    }
}

impl FromStr for Org {
    type Err = NameError;
    fn from_str(text: &str) -> Result<Org, NameError> {
        if text.len() > MAX_NAME_LEN {
            return Err(NameError::TooLong);
        }
        Org::from_labels(&text.split('.').collect::<Vec<_>>())
    }
}

impl TryFrom<String> for Org {
    type Error = NameError;
    fn try_from(text: String) -> Result<Org, NameError> {
        text.parse()
    }
}

impl From<Org> for String {
    fn from(org: Org) -> String {
        org.0
    }
}

impl fmt::Display for Org {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A reverse-DNS identity: `<org>.<kind>.<local>`, e.g. `gg.addis.agent.ava`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Name {
    org: Org,
    kind: Kind,
    local: String,
}

impl Name {
    pub fn new(org: &Org, kind: Kind, local: &str) -> Result<Name, NameError> {
        format!("{org}.{}.{local}", kind.as_str()).parse()
    }

    pub fn org(&self) -> &Org {
        &self.org
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn local(&self) -> &str {
        &self.local
    }

    /// Parses `text` and requires it to be of `kind`.
    pub fn of_kind(text: &str, kind: Kind) -> Result<Name, NameError> {
        let name: Name = text.parse()?;
        if name.kind != kind {
            return Err(NameError::WrongKind { expected: kind, found: name.kind });
        }
        Ok(name)
    }
}

impl FromStr for Name {
    type Err = NameError;
    fn from_str(text: &str) -> Result<Name, NameError> {
        if text.len() > MAX_NAME_LEN {
            return Err(NameError::TooLong);
        }
        let labels: Vec<&str> = text.split('.').collect();
        // The kind is the first reserved word; everything before it is the org.
        let at = labels.iter().position(|label| Kind::parse(label).is_some()).ok_or(NameError::NoKind)?;
        let org = Org::from_labels(&labels[..at])?;
        let kind = Kind::parse(labels[at]).expect("found above");
        let local = match &labels[at + 1..] {
            [] => return Err(NameError::LocalMissing),
            [local] => *local,
            _ => return Err(NameError::LocalTooLong),
        };
        if !valid_label(local) {
            return Err(NameError::BadLabel(local.to_string()));
        }
        Ok(Name { org, kind, local: local.to_string() })
    }
}

impl TryFrom<String> for Name {
    type Error = NameError;
    fn try_from(text: String) -> Result<Name, NameError> {
        text.parse()
    }
}

impl From<Name> for String {
    fn from(name: Name) -> String {
        name.to_string()
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.org, self.kind.as_str(), self.local)
    }
}

/// Matches names of one kind in one org: an exact name, or a local part ending
/// in `*` (`gg.addis.agent.*`, `gg.addis.zone.vm-*`). Never spans kinds or orgs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NamePattern {
    org: Org,
    kind: Kind,
    /// The local part, or its prefix when `wildcard`.
    local: String,
    wildcard: bool,
}

impl NamePattern {
    pub fn matches(&self, name: &Name) -> bool {
        name.org == self.org
            && name.kind == self.kind
            && if self.wildcard { name.local.starts_with(&self.local) } else { name.local == self.local }
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }
}

impl FromStr for NamePattern {
    type Err = NameError;
    fn from_str(text: &str) -> Result<NamePattern, NameError> {
        let Some(prefix) = text.strip_suffix('*') else {
            let name: Name = text.parse()?;
            return Ok(NamePattern { org: name.org, kind: name.kind, local: name.local, wildcard: false });
        };
        // Check the shape with a stand-in local part, then keep the real prefix.
        let probe = format!("{prefix}x");
        let name: Name = probe.parse()?;
        let local = name.local.strip_suffix('x').expect("probe ends in x").to_string();
        Ok(NamePattern { org: name.org, kind: name.kind, local, wildcard: true })
    }
}

impl TryFrom<String> for NamePattern {
    type Error = NameError;
    fn try_from(text: String) -> Result<NamePattern, NameError> {
        text.parse()
    }
}

impl From<NamePattern> for String {
    fn from(pattern: NamePattern) -> String {
        pattern.to_string()
    }
}

impl fmt::Display for NamePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}{}", self.org, self.kind.as_str(), self.local, if self.wildcard { "*" } else { "" })
    }
}

/// Exact text, or a prefix ending in `*`. Used for secret paths, audiences and scopes.
fn text_matches(pattern: &str, text: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => text.starts_with(prefix),
        None => pattern == text,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZoneKind {
    Machine,
    Vm,
    Container,
    Sandbox,
    Service,
    Run,
}

impl ZoneKind {
    /// Short-lived kinds get ids that are never reused, so a new zone never
    /// takes over an old one's history or rights.
    fn fresh_id_prefix(self) -> Option<&'static str> {
        match self {
            ZoneKind::Vm => Some("vm-"),
            ZoneKind::Container => Some("ct-"),
            ZoneKind::Sandbox => Some("sb-"),
            ZoneKind::Run => Some("run-"),
            ZoneKind::Machine | ZoneKind::Service => None,
        }
    }
}

/// Where code runs. A zone's parent is a field: its name never implies one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Zone {
    pub name: Name,
    pub kind: ZoneKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<Name>,
    /// The broker that registered it and vouches for which caller it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker: Option<Name>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<Name>,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub revoked: bool,
}

/// What kind of zone a broker may start, and what bindings match it by.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub name: Name,
    pub kinds: Vec<ZoneKind>,
    pub max_seconds: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verb {
    Read,
    Write,
    Token,
    Launch,
    Approve,
}

/// One thing a role allows. `resource` is a secret path pattern (read/write),
/// an audience pattern (token, with `scopes`), a profile name (launch), or an
/// approval class pattern (approve).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permission {
    pub verb: Verb,
    pub resource: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

impl Permission {
    fn covers(&self, action: &Action) -> bool {
        match action {
            Action::Read { path } => self.verb == Verb::Read && text_matches(&self.resource, path),
            Action::Write { path } => self.verb == Verb::Write && text_matches(&self.resource, path),
            Action::Token { audience, scopes } => {
                self.verb == Verb::Token
                    && text_matches(&self.resource, audience)
                    && scopes.iter().all(|scope| self.scopes.iter().any(|allowed| text_matches(allowed, scope)))
            }
            Action::Launch { profile } => self.verb == Verb::Launch && self.resource == profile.to_string(),
            Action::Approve { class } => self.verb == Verb::Approve && text_matches(&self.resource, class),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub name: Name,
    pub allows: Vec<Permission>,
}

/// Which zones a binding applies to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZoneMatch {
    /// Zones by name (exact, or a `*` prefix).
    Name(NamePattern),
    /// Zones started with this profile, wherever they run.
    Profile(Name),
}

impl ZoneMatch {
    fn matches(&self, zone: &Zone) -> bool {
        match self {
            ZoneMatch::Name(pattern) => pattern.matches(&zone.name),
            ZoneMatch::Profile(profile) => zone.profile.as_ref() == Some(profile),
        }
    }
}

/// `actor × zone → role`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub actor: NamePattern,
    pub zone: ZoneMatch,
    pub role: Name,
}

/// One org's policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub org: Org,
    #[serde(default)]
    pub roles: Vec<Role>,
    #[serde(default)]
    pub bindings: Vec<Binding>,
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub zones: HashMap<Name, Zone>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "lowercase")]
pub enum Action {
    Read { path: String },
    Write { path: String },
    Token { audience: String, scopes: Vec<String> },
    Launch { profile: Name },
    Approve { class: String },
}

/// What a session lets the actor do: a subset of what its starter could.
/// A session only narrows (rule 3); it never adds.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reach {
    pub allows: Vec<Permission>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub actor: &'a Name,
    pub zone: &'a Name,
    pub action: &'a Action,
    /// Set when the actor acts for someone inside a session.
    pub session: Option<&'a Reach>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow { by_role: Name },
    Deny(Denied),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denied {
    ForeignOrg,
    NotAnActor,
    UnknownZone,
    ZoneNotLive,
    NoBinding,
    OutsideSession,
}

impl Denied {
    pub fn as_str(self) -> &'static str {
        match self {
            Denied::ForeignOrg => "foreign_org",
            Denied::NotAnActor => "not_an_actor",
            Denied::UnknownZone => "unknown_zone",
            Denied::ZoneNotLive => "zone_not_live",
            Denied::NoBinding => "no_binding",
            Denied::OutsideSession => "outside_session",
        }
    }
}

impl Policy {
    pub fn new(org: Org) -> Policy {
        Policy { org, roles: Vec::new(), bindings: Vec::new(), profiles: Vec::new(), zones: HashMap::new() }
    }

    fn role(&self, name: &Name) -> Option<&Role> {
        self.roles.iter().find(|role| &role.name == name)
    }

    fn profile(&self, name: &Name) -> Option<&Profile> {
        self.profiles.iter().find(|profile| &profile.name == name)
    }

    /// A zone is live when it, and every zone above it, is registered,
    /// unrevoked and unexpired.
    pub fn zone_is_live(&self, name: &Name, now: u64) -> bool {
        let mut current = name;
        for _ in 0..MAX_ZONE_DEPTH {
            let Some(zone) = self.zones.get(current) else { return false };
            if zone.revoked || zone.expires_at.is_some_and(|at| at <= now) {
                return false;
            }
            match &zone.parent {
                None => return true,
                Some(parent) => current = parent,
            }
        }
        false
    }

    /// The request rule (architecture, section 3). Every decision goes through
    /// here: the actor and the zone both count, and nothing flows from a
    /// zone's parent.
    pub fn decide(&self, request: &Request<'_>, now: u64) -> Decision {
        if request.actor.org() != &self.org || request.zone.org() != &self.org {
            return Decision::Deny(Denied::ForeignOrg);
        }
        if !request.actor.kind().is_actor() {
            return Decision::Deny(Denied::NotAnActor);
        }
        let Some(zone) = self.zones.get(request.zone) else {
            return Decision::Deny(Denied::UnknownZone);
        };
        if !self.zone_is_live(request.zone, now) {
            return Decision::Deny(Denied::ZoneNotLive);
        }
        let by_role = self
            .bindings
            .iter()
            .filter(|binding| binding.actor.matches(request.actor) && binding.zone.matches(zone))
            .filter_map(|binding| self.role(&binding.role))
            .find(|role| role.allows.iter().any(|permission| permission.covers(request.action)));
        let Some(role) = by_role else {
            return Decision::Deny(Denied::NoBinding);
        };
        if let Some(reach) = request.session {
            if !reach.allows.iter().any(|permission| permission.covers(request.action)) {
                return Decision::Deny(Denied::OutsideSession);
            }
        }
        Decision::Allow { by_role: role.name.clone() }
    }

    /// Registers a zone a broker started. The broker must be allowed to launch
    /// the profile from its own machine zone; the profile must admit the kind;
    /// the zone may live no longer than the profile allows, nor outlive its
    /// parent's own expiry. The new zone gets nothing from its parent: only
    /// bindings that match its profile apply to it.
    pub fn register_child(&mut self, ask: ChildZone, now: u64) -> Result<&Zone, RegisterError> {
        if ask.name.kind() != Kind::Zone || ask.name.org() != &self.org {
            return Err(RegisterError::BadName);
        }
        if let Some(prefix) = ask.kind.fresh_id_prefix() {
            let id = ask.name.local().strip_prefix(prefix).ok_or(RegisterError::NotFreshId)?;
            if id.len() < 16 {
                return Err(RegisterError::NotFreshId);
            }
        }
        if self.zones.contains_key(&ask.name) {
            return Err(RegisterError::NameTaken);
        }
        let parent = self.zones.get(&ask.parent).ok_or(RegisterError::ParentNotLive)?;
        if !self.zone_is_live(&ask.parent, now) {
            return Err(RegisterError::ParentNotLive);
        }
        let launch = Action::Launch { profile: ask.profile.clone() };
        let request = Request { actor: &ask.broker, zone: &ask.parent, action: &launch, session: None };
        if !matches!(self.decide(&request, now), Decision::Allow { .. }) {
            return Err(RegisterError::MayNotLaunch);
        }
        let profile = self.profile(&ask.profile).ok_or(RegisterError::UnknownProfile)?;
        if !profile.kinds.contains(&ask.kind) {
            return Err(RegisterError::KindNotInProfile);
        }
        let mut expires_at = now + ask.seconds.min(profile.max_seconds);
        if let Some(parent_end) = parent.expires_at {
            expires_at = expires_at.min(parent_end);
        }
        let zone = Zone {
            name: ask.name.clone(),
            kind: ask.kind,
            parent: Some(ask.parent),
            broker: Some(ask.broker),
            profile: Some(ask.profile),
            created_at: now,
            expires_at: Some(expires_at),
            revoked: false,
        };
        Ok(self.zones.entry(ask.name).or_insert(zone))
    }
}

/// A broker's request to register a zone it started.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildZone {
    pub name: Name,
    pub kind: ZoneKind,
    pub parent: Name,
    pub broker: Name,
    pub profile: Name,
    /// How long the zone should live; capped by the profile.
    pub seconds: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterError {
    BadName,
    NotFreshId,
    NameTaken,
    ParentNotLive,
    MayNotLaunch,
    UnknownProfile,
    KindNotInProfile,
}

impl RegisterError {
    pub fn as_str(self) -> &'static str {
        match self {
            RegisterError::BadName => "bad_name",
            RegisterError::NotFreshId => "not_a_fresh_id",
            RegisterError::NameTaken => "name_taken",
            RegisterError::ParentNotLive => "parent_not_live",
            RegisterError::MayNotLaunch => "may_not_launch",
            RegisterError::UnknownProfile => "unknown_profile",
            RegisterError::KindNotInProfile => "kind_not_in_profile",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const VM: &str = "gg.addis.zone.vm-01jbx4k2m9q8r7s6";

    fn name(text: &str) -> Name {
        text.parse().unwrap()
    }

    fn pattern(text: &str) -> NamePattern {
        text.parse().unwrap()
    }

    fn read(path: &str) -> Action {
        Action::Read { path: path.into() }
    }

    fn permission(verb: Verb, resource: &str) -> Permission {
        Permission { verb, resource: resource.into(), scopes: Vec::new() }
    }

    fn decide(policy: &Policy, actor: &str, zone: &str, action: &Action) -> Decision {
        policy.decide(&Request { actor: &name(actor), zone: &name(zone), action, session: None }, NOW)
    }

    fn denied(reason: Denied) -> Decision {
        Decision::Deny(reason)
    }

    /// demon is a machine zone whose broker may launch build VMs. The site
    /// service on demon may read prod/site/*. Agents in build VMs may read
    /// build/* and nothing else.
    fn addis() -> Policy {
        let mut policy = Policy::new("gg.addis".parse().unwrap());
        policy.zones.insert(
            name("gg.addis.zone.demon"),
            Zone {
                name: name("gg.addis.zone.demon"),
                kind: ZoneKind::Machine,
                parent: None,
                broker: None,
                profile: None,
                created_at: NOW - 100,
                expires_at: None,
                revoked: false,
            },
        );
        policy.profiles.push(Profile {
            name: name("gg.addis.profile.build-vm"),
            kinds: vec![ZoneKind::Vm],
            max_seconds: 3600,
        });
        policy.roles.push(Role {
            name: name("gg.addis.role.site-runtime"),
            allows: vec![permission(Verb::Read, "prod/site/*")],
        });
        policy.roles.push(Role {
            name: name("gg.addis.role.demon-broker"),
            allows: vec![permission(Verb::Launch, "gg.addis.profile.build-vm"), permission(Verb::Read, "prod/*")],
        });
        policy.roles.push(Role {
            name: name("gg.addis.role.build"),
            allows: vec![
                permission(Verb::Read, "build/*"),
                Permission { verb: Verb::Token, resource: "https://api.simien.dev".into(), scopes: vec!["deploy:*".into()] },
            ],
        });
        policy.bindings.push(Binding {
            actor: pattern("gg.addis.service.site"),
            zone: ZoneMatch::Name(pattern("gg.addis.zone.demon")),
            role: name("gg.addis.role.site-runtime"),
        });
        policy.bindings.push(Binding {
            actor: pattern("gg.addis.broker.demon"),
            zone: ZoneMatch::Name(pattern("gg.addis.zone.demon")),
            role: name("gg.addis.role.demon-broker"),
        });
        policy.bindings.push(Binding {
            actor: pattern("gg.addis.agent.*"),
            zone: ZoneMatch::Profile(name("gg.addis.profile.build-vm")),
            role: name("gg.addis.role.build"),
        });
        policy
    }

    fn launch_vm(policy: &mut Policy, seconds: u64) -> Result<Zone, RegisterError> {
        policy
            .register_child(
                ChildZone {
                    name: name(VM),
                    kind: ZoneKind::Vm,
                    parent: name("gg.addis.zone.demon"),
                    broker: name("gg.addis.broker.demon"),
                    profile: name("gg.addis.profile.build-vm"),
                    seconds,
                },
                NOW,
            )
            .cloned()
    }

    #[test]
    fn names_parse_and_print_back() {
        let ava = name("gg.addis.agent.ava");
        assert_eq!(ava.org().as_str(), "gg.addis");
        assert_eq!(ava.kind(), Kind::Agent);
        assert_eq!(ava.local(), "ava");
        assert_eq!(ava.to_string(), "gg.addis.agent.ava");
        assert_eq!(name("com.acme.eu.human.jane").org().as_str(), "com.acme.eu");
        assert_eq!(Name::new(&"gg.addis".parse().unwrap(), Kind::Broker, "imac").unwrap(), name("gg.addis.broker.imac"));
        let json = serde_json::to_string(&ava).unwrap();
        assert_eq!(json, r#""gg.addis.agent.ava""#);
        assert_eq!(serde_json::from_str::<Name>(&json).unwrap(), ava);
    }

    #[test]
    fn malformed_names_are_refused() {
        let refused = |text: &str| text.parse::<Name>().unwrap_err();
        assert_eq!(refused("addis.agent.ava"), NameError::OrgTooShort);
        assert_eq!(refused("gg.addis.ava"), NameError::NoKind);
        assert_eq!(refused("gg.addis.agent"), NameError::LocalMissing);
        assert_eq!(refused("gg.addis.agent.ava.sub"), NameError::LocalTooLong);
        assert_eq!(refused("gg.addis.agent.Ava"), NameError::BadLabel("Ava".into()));
        assert_eq!(refused("gg.addis.agent.-ava"), NameError::BadLabel("-ava".into()));
        assert_eq!(refused("gg..agent.ava"), NameError::BadLabel("".into()));
        assert_eq!(refused(&format!("gg.addis.agent.{}", "a".repeat(64))), NameError::BadLabel("a".repeat(64)));
        assert_eq!(refused(&format!("{}.agent.ava", "a.".repeat(130))), NameError::TooLong);
        // The first kind word ends the org, so a kind can never hide inside one.
        assert_eq!(refused("gg.zone.addis.agent.ava"), NameError::OrgTooShort);
        assert!(serde_json::from_str::<Name>(r#""gg.addis.ava""#).is_err());
        assert_eq!(Name::of_kind("gg.addis.agent.ava", Kind::Human).unwrap_err(), NameError::WrongKind { expected: Kind::Human, found: Kind::Agent });
    }

    #[test]
    fn patterns_stay_inside_one_kind_and_one_org() {
        let agents = pattern("gg.addis.agent.*");
        assert!(agents.matches(&name("gg.addis.agent.ava")));
        assert!(!agents.matches(&name("gg.addis.human.sami")));
        assert!(!agents.matches(&name("com.acme.agent.ava")));
        let vms = pattern("gg.addis.zone.vm-*");
        assert!(vms.matches(&name(VM)));
        assert!(!vms.matches(&name("gg.addis.zone.demon")));
        assert!("gg.addis.*".parse::<NamePattern>().is_err(), "a pattern always names a kind");
        assert_eq!(vms.to_string(), "gg.addis.zone.vm-*");
    }

    #[test]
    fn actor_and_zone_both_decide() {
        let policy = addis();
        assert_eq!(
            decide(&policy, "gg.addis.service.site", "gg.addis.zone.demon", &read("prod/site/DATABASE_URL")),
            Decision::Allow { by_role: name("gg.addis.role.site-runtime") }
        );
        assert_eq!(decide(&policy, "gg.addis.service.site", "gg.addis.zone.demon", &read("prod/other/KEY")), denied(Denied::NoBinding));
        assert_eq!(decide(&policy, "gg.addis.service.gild", "gg.addis.zone.demon", &read("prod/site/DATABASE_URL")), denied(Denied::NoBinding));
        assert_eq!(decide(&policy, "gg.addis.service.site", "gg.addis.zone.bugsy", &read("prod/site/DATABASE_URL")), denied(Denied::UnknownZone));
        assert_eq!(decide(&policy, "com.acme.service.site", "gg.addis.zone.demon", &read("prod/site/DATABASE_URL")), denied(Denied::ForeignOrg));
        assert_eq!(decide(&policy, "gg.addis.role.site-runtime", "gg.addis.zone.demon", &read("prod/site/DATABASE_URL")), denied(Denied::NotAnActor));
    }

    #[test]
    fn a_child_zone_gets_nothing_from_its_parent() {
        let mut policy = addis();
        let vm = launch_vm(&mut policy, 600).unwrap();
        assert_eq!(vm.parent, Some(name("gg.addis.zone.demon")));
        assert_eq!(vm.expires_at, Some(NOW + 600));

        // demon's broker may read prod/*, and the site service on demon may read
        // prod/site/*. Neither carries into the VM demon started.
        assert!(matches!(decide(&policy, "gg.addis.broker.demon", "gg.addis.zone.demon", &read("prod/site/X")), Decision::Allow { .. }));
        assert_eq!(decide(&policy, "gg.addis.broker.demon", VM, &read("prod/site/X")), denied(Denied::NoBinding));
        assert_eq!(decide(&policy, "gg.addis.service.site", VM, &read("prod/site/X")), denied(Denied::NoBinding));

        // Only what bindings give the build-vm profile applies inside it.
        assert_eq!(decide(&policy, "gg.addis.agent.ava", VM, &read("build/cache-key")), Decision::Allow { by_role: name("gg.addis.role.build") });
        assert_eq!(decide(&policy, "gg.addis.agent.ava", VM, &read("prod/site/X")), denied(Denied::NoBinding));
        assert_eq!(decide(&policy, "gg.addis.agent.ava", "gg.addis.zone.demon", &read("build/cache-key")), denied(Denied::NoBinding));
    }

    #[test]
    fn brokers_launch_only_what_they_are_allowed_and_never_for_longer() {
        let mut policy = addis();
        assert_eq!(launch_vm(&mut policy, 999_999).unwrap().expires_at, Some(NOW + 3600), "capped by the profile");
        assert_eq!(launch_vm(&mut policy, 60).unwrap_err(), RegisterError::NameTaken);

        let ask = |zone: &str, kind: ZoneKind, broker: &str, profile: &str| ChildZone {
            name: name(zone),
            kind,
            parent: name("gg.addis.zone.demon"),
            broker: name(broker),
            profile: name(profile),
            seconds: 60,
        };
        let mut fresh = addis();
        let other_vm = "gg.addis.zone.vm-01jbx4k2m9q8r7zz";
        assert_eq!(fresh.register_child(ask(other_vm, ZoneKind::Vm, "gg.addis.broker.bugsy", "gg.addis.profile.build-vm"), NOW).unwrap_err(), RegisterError::MayNotLaunch);
        assert_eq!(fresh.register_child(ask(other_vm, ZoneKind::Vm, "gg.addis.broker.demon", "gg.addis.profile.prod-vm"), NOW).unwrap_err(), RegisterError::MayNotLaunch);
        assert_eq!(fresh.register_child(ask("gg.addis.zone.ct-01jbx4k2m9q8r7s6", ZoneKind::Container, "gg.addis.broker.demon", "gg.addis.profile.build-vm"), NOW).unwrap_err(), RegisterError::KindNotInProfile);
        assert_eq!(fresh.register_child(ask("gg.addis.zone.vm9863", ZoneKind::Vm, "gg.addis.broker.demon", "gg.addis.profile.build-vm"), NOW).unwrap_err(), RegisterError::NotFreshId);
        assert_eq!(fresh.register_child(ask("gg.addis.zone.vm-short", ZoneKind::Vm, "gg.addis.broker.demon", "gg.addis.profile.build-vm"), NOW).unwrap_err(), RegisterError::NotFreshId);
        assert_eq!(fresh.register_child(ask("gg.addis.agent.vm-01jbx4k2m9q8r7s6", ZoneKind::Vm, "gg.addis.broker.demon", "gg.addis.profile.build-vm"), NOW).unwrap_err(), RegisterError::BadName);
    }

    #[test]
    fn a_revoked_or_expired_parent_ends_every_zone_under_it() {
        let mut policy = addis();
        launch_vm(&mut policy, 600).unwrap();
        let build = read("build/cache-key");
        let at = |policy: &Policy, now: u64| {
            policy.decide(&Request { actor: &name("gg.addis.agent.ava"), zone: &name(VM), action: &build, session: None }, now)
        };
        assert!(matches!(at(&policy, NOW + 1), Decision::Allow { .. }));
        assert_eq!(at(&policy, NOW + 600), denied(Denied::ZoneNotLive), "the VM's own expiry");

        policy.zones.get_mut(&name("gg.addis.zone.demon")).unwrap().revoked = true;
        assert_eq!(at(&policy, NOW + 1), denied(Denied::ZoneNotLive), "its machine was removed");
        let again = ChildZone {
            name: name("gg.addis.zone.vm-01jbx4k2m9q8r7aa"),
            kind: ZoneKind::Vm,
            parent: name("gg.addis.zone.demon"),
            broker: name("gg.addis.broker.demon"),
            profile: name("gg.addis.profile.build-vm"),
            seconds: 60,
        };
        assert_eq!(policy.register_child(again, NOW).unwrap_err(), RegisterError::ParentNotLive);
    }

    #[test]
    fn a_session_only_narrows() {
        let mut policy = addis();
        launch_vm(&mut policy, 600).unwrap();
        let reach = Reach { allows: vec![permission(Verb::Read, "build/cache-*")] };
        let with = |action: &Action| {
            policy.decide(&Request { actor: &name("gg.addis.agent.ava"), zone: &name(VM), action, session: Some(&reach) }, NOW)
        };
        assert!(matches!(with(&read("build/cache-key")), Decision::Allow { .. }));
        assert_eq!(with(&read("build/signing-key")), denied(Denied::OutsideSession), "the role allows it, the session doesn't");
        let wide = Reach { allows: vec![permission(Verb::Read, "*")] };
        let wider = policy.decide(&Request { actor: &name("gg.addis.agent.ava"), zone: &name(VM), action: &read("prod/site/X"), session: Some(&wide) }, NOW);
        assert_eq!(wider, denied(Denied::NoBinding), "a wide session adds nothing the bindings don't give");
    }

    #[test]
    fn token_permissions_check_audience_and_every_scope() {
        let mut policy = addis();
        launch_vm(&mut policy, 600).unwrap();
        let token = |audience: &str, scopes: &[&str]| Action::Token { audience: audience.into(), scopes: scopes.iter().map(|s| s.to_string()).collect() };
        assert!(matches!(decide(&policy, "gg.addis.agent.ava", VM, &token("https://api.simien.dev", &["deploy:site"])), Decision::Allow { .. }));
        assert_eq!(decide(&policy, "gg.addis.agent.ava", VM, &token("https://api.simien.dev", &["deploy:site", "admin"])), denied(Denied::NoBinding));
        assert_eq!(decide(&policy, "gg.addis.agent.ava", VM, &token("https://gild.gg", &["deploy:site"])), denied(Denied::NoBinding));
    }

    #[test]
    fn policies_round_trip_through_json() {
        let mut policy = addis();
        launch_vm(&mut policy, 600).unwrap();
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains(r#""actor":"gg.addis.agent.*""#));
        assert!(json.contains(r#""profile":"gg.addis.profile.build-vm""#));
        assert_eq!(serde_json::from_str::<Policy>(&json).unwrap(), policy);
    }
}
