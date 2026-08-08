//! The `followee` command-line client (IMPLEMENTATION.md section 8).
//!
//! This binary is a thin shim: all behaviour lives in [`followee::cli`],
//! which receives the operating-system clock and CSPRNG here and
//! deterministic implementations in tests.

use followee::clock::SystemClock;
use followee::random::OsRandom;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    ExitCode::from(followee::cli::run(
        &args,
        &OsRandom,
        &SystemClock,
        &mut stdout,
        &mut stderr,
    ))
}
