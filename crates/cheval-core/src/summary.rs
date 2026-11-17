//! The result of a sync run, shared by the engine, the status streams and the daemon.
use crate::util::{self, human_bytes};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Default)]
pub struct RepoOutcome {
    pub name: String,
    pub root: PathBuf,
    pub ran: bool,
    pub complete: bool,
    pub cancelled: bool,
    pub suites_ok: Vec<String>,
    pub suites_failed: Vec<(String, String)>,
    pub files_fetched: u64,
    pub bytes_fetched: u64,
    pub files_present: u64,
    pub files_failed: u64,
    pub pending_files: u64,
    pub pending_bytes: u64,
    pub expected: HashSet<PathBuf>,
}

#[derive(Debug, Default)]
pub struct Summary {
    pub repos: Vec<RepoOutcome>,
    pub cleaned_files: u64,
    pub cleaned_bytes: u64,
    pub cancelled: bool,
    pub dry_run: bool,
    pub elapsed: Duration,
}

impl Summary {
    pub fn success(&self) -> bool {
        !self.cancelled
            && self.repos.iter().all(|r| !r.ran || (r.complete || self.dry_run) && r.suites_failed.is_empty())
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "\ncheval {} in {}\n",
            if self.cancelled {
                "CANCELLED"
            } else if self.success() {
                if self.dry_run { "dry run finished" } else { "finished successfully" }
            } else {
                "finished WITH ERRORS"
            },
            util::human_duration(self.elapsed.as_secs())
        ));
        for r in &self.repos {
            if !r.ran {
                s.push_str(&format!("  {:<24} skipped\n", r.name));
                continue;
            }
            let state = if r.cancelled {
                "cancelled"
            } else if r.suites_failed.is_empty() {
                "ok"
            } else if r.suites_ok.is_empty() {
                "FAILED"
            } else {
                "PARTIAL"
            };
            s.push_str(&format!(
                "  {:<24} {:<9} fetched {} files ({}), {} already present, {} failed\n",
                r.name,
                state,
                r.files_fetched,
                human_bytes(r.bytes_fetched),
                r.files_present,
                r.files_failed
            ));
            if self.dry_run {
                s.push_str(&format!(
                    "  {:<24} would download {} files ({})\n",
                    "",
                    r.pending_files,
                    human_bytes(r.pending_bytes)
                ));
            }
            for (suite, why) in &r.suites_failed {
                s.push_str(&format!("      suite {suite}: {why}\n"));
            }
        }
        if self.cleaned_files > 0 {
            s.push_str(&format!(
                "  cleaned {} obsolete files ({})\n",
                self.cleaned_files,
                human_bytes(self.cleaned_bytes)
            ));
        }
        s
    }
}
