//! Status reporting for cheval: messages, sinks (UDP/TCP/syslog), the HTTP API and the
//! receiver for the far side of a data diode.

// Re-exported so modules keep addressing them as `crate::…`.
pub use cheval_core::{config, logo, progress, summary, util};

pub mod api;
pub mod listen;
pub mod sink;
pub mod status;
