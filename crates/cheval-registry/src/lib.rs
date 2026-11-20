//! Package registries: a chosen set of packages, with what they depend on, mirrored so the
//! stock clients (cargo, go, mvn) can use the mirror under the upstream host names.
//!
//! - `format = "crates"`: a sparse cargo index (`index.crates.io`) and its crate files
//!   (`static.crates.io`). Index files are rewritten to list only mirrored versions.
//! - `format = "go"`: a Go module proxy (`proxy.golang.org`): `.info`, `.mod`, `.zip` and
//!   `@v/list` for the mirrored versions.
//! - `format = "maven"`: a Maven 2 repository (`repo.maven.apache.org/maven2`): POMs,
//!   artifacts, their `.sha1` files and `maven-metadata.xml` for the mirrored versions.
//!
//! Mirrors are additive: a version once mirrored stays (and stays listed) until its files
//! are deleted from the mirror. Index and listing files are published last, after every
//! file they list is in place; if anything fails they are not replaced.

// Re-exported so modules keep addressing them as `crate::…`.
pub use cheval_core::{config, http, progress, summary, util};

pub mod cargo;
pub mod engine;
pub mod go;
pub mod maven;
pub mod verify;

pub use engine::{Env, sync_entry};
