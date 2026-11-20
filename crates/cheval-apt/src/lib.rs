//! The APT backend of cheval: Release and index parsing, the sync engine, verify, probe,
//! and sources.list import.

// Re-exported so modules keep addressing them as `crate::…`.
pub use cheval_core::{config, http, lock, meter, progress, sig, summary, util};
pub use cheval_status::status;

pub mod clean;
pub mod deb822;
pub mod import;
pub mod plan;
pub mod probe;
pub mod release;
pub mod sync;
pub mod verify;
