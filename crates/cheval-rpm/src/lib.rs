//! The RPM side of cheval: yum/dnf repositories (`format = "rpm"`) and folders of files
//! listed in a checksum file, such as installer ISOs (`format = "files"`).
//!
//! Repositories are mirrored verbatim: every metadata file `repodata/repomd.xml` lists is
//! fetched and checked, the packages `primary.xml` lists are fetched and checked, and
//! `repomd.xml` is published last so clients never see a half-updated repository.

// Re-exported so modules keep addressing them as `crate::…`.
pub use cheval_core::{config, http, lock, meter, progress, sig, summary, util};
pub use cheval_status::status;

pub mod meta;
pub mod sums;
pub mod sync;
