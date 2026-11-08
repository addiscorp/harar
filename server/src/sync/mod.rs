//! Sync between ring members through an edge (docs/edge.md §5a, §5b): the
//! agent's vault as one member of a ring that shares one vault.

pub(crate) mod apply;
pub(crate) mod crypto;
pub(crate) mod ledger;
pub(crate) mod member;
pub(crate) mod op;
#[cfg(test)]
mod review_tests;
#[cfg(test)]
mod tests;
