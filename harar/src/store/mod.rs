//! Where the primary keeps its secrets.

// `harar serve` moves onto this store in the next change (#43); until then
// only the tests below use it.
#![allow(dead_code)]

pub mod envelope;
pub mod postgres;
