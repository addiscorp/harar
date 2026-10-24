//! Where the primary keeps its secrets.

// History (`versions`, `get_version`) and master key rotation (`rewrap`) have
// no command yet; they come with approvals (#45).
#![allow(dead_code)]

pub mod envelope;
pub mod postgres;
