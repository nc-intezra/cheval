//! Offline transfer for cheval: incremental bundles and hard-link snapshots. Format
//! agnostic: works on the mirror tree as files.

// Re-exported so modules keep addressing them as `crate::…`.
pub use cheval_core::{config, lock, logo, util};

pub mod bundle;
pub mod meter;
pub mod snapshot;
