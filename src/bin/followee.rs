//! Placeholder binary for the eventual `followee` command-line client.
//!
//! The CLI surface is a Milestone 2 deliverable (IMPLEMENTATION.md section 8).
//! Until then this stub only reports that no protocol behaviour exists, and
//! exits nonzero so scripts cannot mistake it for a working tool.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "followee {} (Milestone 0 scaffold): no protocol behaviour is implemented yet.",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!("See IMPLEMENTATION.md for the milestone plan.");
    ExitCode::from(2)
}
