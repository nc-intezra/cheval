//! Shared foundation of cheval: configuration, HTTP, hashing, signatures, progress,
//! run summary, run lock and schedules. Nothing here knows a repository format beyond what
//! the configuration describes.

pub mod config;
pub mod http;
pub mod lock;
pub mod logo;
pub mod meter;
pub mod progress;
pub mod schedule;
pub mod sig;
pub mod summary;
pub mod util;
