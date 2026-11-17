//! The cheval terminal UI and the plain-text progress output used without one.

// Re-exported so modules keep addressing them as `crate::…`.
pub use cheval_core::{logo, progress, util};

pub mod headless;
pub mod tui;
