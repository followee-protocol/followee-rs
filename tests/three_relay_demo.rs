//! Runs the complete deterministic three-relay shell demonstration
//! (IMPLEMENTATION.md section 13 Milestone 4): three real `followee relay
//! serve` processes, loopback port-0 binding, isolated SQLite databases,
//! explicit readiness signals, and the production binary command surfaces.
#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;

#[test]
fn milestone_4_three_relay_demonstration_passes() {
    let followee = PathBuf::from(env!("CARGO_BIN_EXE_followee"));
    // `cargo test --all-targets` builds examples into the same profile
    // directory as the binary; other harnesses (for example `cargo
    // llvm-cov`) may not, in which case the script builds it itself.
    let housekeeping = followee
        .parent()
        .expect("target dir")
        .join("examples/relay_housekeeping");
    let workdir = tempfile::tempdir().expect("workdir");
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("demo/three_relay_demo.sh");
    let mut command = Command::new("bash");
    command
        .arg(&script)
        .env("FOLLOWEE_BIN", &followee)
        .env("DEMO_WORKDIR", workdir.path())
        .current_dir(env!("CARGO_MANIFEST_DIR"));
    if housekeeping.exists() {
        command.env("HOUSEKEEPING_BIN", &housekeeping);
    } else {
        // Let the script build the example with an uninstrumented default
        // profile so coverage instrumentation flags do not leak into it.
        command
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_TARGET_DIR");
    }
    let output = command.output().expect("demo runs");
    assert!(
        output.status.success(),
        "demo failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for marker in [
        "the three relays hold different partial views",
        "path compression affected only routing state",
        "demonstration complete",
    ] {
        assert!(stdout.contains(marker), "missing {marker:?} in:\n{stdout}");
    }
}
