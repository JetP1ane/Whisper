//! Security-adjacent helpers that don't fit cleanly into `crypto`,
//! `transport`, or `commands`. Currently:
//!
//! - [`egress`] — list this process's open network sockets so the
//!   user can verify nothing is beaconing out unexpectedly.

pub mod egress;
