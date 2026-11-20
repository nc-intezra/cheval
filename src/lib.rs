//! cheval — a consistent, verifiable APT repository mirroring tool.
//!
//! The code lives in the workspace crates (`crates/`); this crate is the `cheval` binary and
//! re-exports every module under its long-standing `cheval::…` path. `daemon` and `ingest`
//! live here because they tie the pieces together (sync + status, bundles + verify).
pub use cheval_apt::{clean, deb822, import, plan, probe, release, sync, verify};
pub use cheval_bundle::{bundle, snapshot};
pub use cheval_core::{config, http, lock, logo, meter, progress, schedule, sig, summary, util};
pub use cheval_status::{api, listen, sink, status};
pub use cheval_tui::{headless, tui};

pub mod daemon;
pub mod ingest;
