//! Local secret-seed storage for the demonstration CLI
//! (IMPLEMENTATION.md section 7.4).
//!
//! This is an application format, not part of the Followee protocol: 32-byte
//! Ed25519 seeds in tagged single-line files. Root and revocation seeds are
//! written to separately named caller-chosen paths (the revocation path may
//! point at removable media). New files are created atomically with
//! owner-only permissions; existing files are never overwritten without the
//! explicit force flag, and replacement goes through an owner-only temporary
//! file renamed into place. Loading refuses group/other-accessible files,
//! non-regular files, and every published Appendix B test seed. Seed bytes
//! are zeroised on drop and never appear in any output, error, or `Debug`
//! representation.

use crate::random::RandomSource;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// The tagged first-line prefix of a seed file.
const SEED_PREFIX: &str = "followee-seed-v1:";

/// A 32-byte secret seed. `Debug` is redacted and the bytes are zeroised on
/// drop; the raw bytes are reachable only through [`SecretSeed::bytes`].
pub struct SecretSeed([u8; 32]);

impl SecretSeed {
    /// Wraps freshly generated or loaded seed bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        SecretSeed(bytes)
    }

    /// The raw seed bytes, for signing only.
    #[must_use]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SecretSeed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecretSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the bytes: a stray `{:?}` in any diagnostic stays safe.
        f.write_str("SecretSeed(redacted)")
    }
}

/// Key-storage failure. Messages name paths and conditions, never contents.
#[derive(Debug, thiserror::Error)]
pub enum KeyFileError {
    /// The target file already exists and `--force` was not given.
    #[error("refusing to overwrite existing file {0} without --force")]
    Exists(PathBuf),
    /// The file is not a regular file (symlink, directory, device).
    #[error("{0} is not a regular file")]
    NotRegular(PathBuf),
    /// The file is readable by group or other users.
    #[error("{0} permits group/other access; a seed file must be owner-only (chmod 600)")]
    UnsafePermissions(PathBuf),
    /// The file does not parse as a tagged v1 seed file. The offending
    /// content is deliberately not echoed.
    #[error("{0} is not a followee-seed-v1 file")]
    Malformed(PathBuf),
    /// The seed equals a published Appendix B test seed.
    #[error(
        "{0} contains a published Followee specification test seed; \
         production commands refuse it (Appendix B.1)"
    )]
    PublishedTestSeed(PathBuf),
    /// Underlying filesystem failure.
    #[error("{path}: {source}")]
    Io {
        /// The path involved.
        path: PathBuf,
        /// The operating-system error.
        source: std::io::Error,
    },
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> KeyFileError + '_ {
    move |source| KeyFileError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Every published Appendix B secret seed (specification Appendix B.1: public
/// test material that MUST NOT back a real identity). IMPLEMENTATION.md
/// section 7.4 names the B.2 and B.8 pairs; the B.9 Bob pair, published by
/// the v0.8 amendment under the same Appendix B.1 warning, is refused on the
/// same basis.
const PUBLISHED_SEEDS: [&str; 6] = [
    // B.2 root and revocation.
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    // B.8 attacker root and revocation.
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
    // B.9 Bob root and revocation.
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
];

fn is_published_seed(seed: &[u8; 32]) -> bool {
    let mut lower = hex::encode(seed);
    let published = PUBLISHED_SEEDS.contains(&lower.as_str());
    lower.zeroize();
    published
}

#[cfg(unix)]
fn open_owner_only_new(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_owner_only_new(path: &Path) -> std::io::Result<fs::File> {
    // Owner-only modes are applied where the operating system supports them
    // (IMPLEMENTATION.md section 7.4); elsewhere creation is still exclusive.
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Writes a seed file. Creation is atomic and exclusive (`O_CREAT|O_EXCL`)
/// with owner-only permissions. With `force`, the replacement is written to
/// an owner-only temporary file in the same directory and renamed into
/// place, so no reader ever observes a partial seed.
pub fn write_seed(
    path: &Path,
    seed: &SecretSeed,
    force: bool,
    rng: &dyn RandomSource,
) -> Result<(), KeyFileError> {
    let mut line = format!("{SEED_PREFIX}{}\n", hex::encode(seed.bytes()));
    let result = write_seed_line(path, line.as_bytes(), force, rng);
    line.zeroize();
    result
}

fn write_seed_line(
    path: &Path,
    content: &[u8],
    force: bool,
    rng: &dyn RandomSource,
) -> Result<(), KeyFileError> {
    if !force {
        let mut file = open_owner_only_new(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                KeyFileError::Exists(path.to_path_buf())
            } else {
                KeyFileError::Io {
                    path: path.to_path_buf(),
                    source: e,
                }
            }
        })?;
        file.write_all(content).map_err(io_err(path))?;
        file.sync_all().map_err(io_err(path))?;
        return Ok(());
    }

    // Forced replacement: exclusive owner-only temporary in the same
    // directory, then an atomic rename over the target.
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let mut suffix = [0u8; 8];
    rng.fill(&mut suffix).map_err(|e| KeyFileError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::other(e.to_string()),
    })?;
    let temp = directory.join(format!(".followee-seed-{}.tmp", hex::encode(suffix)));
    let mut file = open_owner_only_new(&temp).map_err(io_err(&temp))?;
    let outcome = file
        .write_all(content)
        .and_then(|()| file.sync_all())
        .map_err(io_err(&temp))
        .and_then(|()| fs::rename(&temp, path).map_err(io_err(path)));
    if outcome.is_err() {
        // Best-effort cleanup; the temporary is owner-only regardless.
        let _ = fs::remove_file(&temp);
    }
    outcome
}

#[cfg(unix)]
fn check_read_safety(path: &Path) -> Result<(), KeyFileError> {
    use std::os::unix::fs::MetadataExt;
    // symlink_metadata: a symlinked seed file is refused rather than
    // followed, so a swapped link cannot redirect secret reads or writes.
    let metadata = fs::symlink_metadata(path).map_err(io_err(path))?;
    if !metadata.is_file() {
        return Err(KeyFileError::NotRegular(path.to_path_buf()));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(KeyFileError::UnsafePermissions(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_read_safety(path: &Path) -> Result<(), KeyFileError> {
    let metadata = fs::symlink_metadata(path).map_err(io_err(path))?;
    if !metadata.is_file() {
        return Err(KeyFileError::NotRegular(path.to_path_buf()));
    }
    Ok(())
}

/// Loads a seed for signing: refuses unsafe paths and permissions, parses
/// the tagged format without echoing contents, and rejects every published
/// Appendix B test seed.
pub fn read_seed(path: &Path) -> Result<SecretSeed, KeyFileError> {
    check_read_safety(path)?;
    let mut text = fs::read_to_string(path).map_err(io_err(path))?;
    let parsed = parse_seed_line(&text);
    text.zeroize();
    let mut bytes = parsed.ok_or_else(|| KeyFileError::Malformed(path.to_path_buf()))?;
    if is_published_seed(&bytes) {
        bytes.zeroize();
        return Err(KeyFileError::PublishedTestSeed(path.to_path_buf()));
    }
    Ok(SecretSeed::new(bytes))
}

fn parse_seed_line(text: &str) -> Option<[u8; 32]> {
    let line = text.strip_suffix('\n').unwrap_or(text);
    let hex_part = line.strip_prefix(SEED_PREFIX)?;
    if hex_part.len() != 64 {
        return None;
    }
    let mut decoded = hex::decode(hex_part).ok()?;
    let result = <[u8; 32]>::try_from(decoded.as_slice()).ok();
    decoded.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::DeterministicRandom;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    fn seed(byte: u8) -> SecretSeed {
        SecretSeed::new([byte; 32])
    }

    #[test]
    fn impl_7_4_write_is_exclusive_owner_only_and_force_replaces_atomically() {
        let dir = temp_dir();
        let path = dir.path().join("root.seed");
        let rng = DeterministicRandom::from_seed(7);
        write_seed(&path, &seed(0x11), false, &rng).expect("first write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let mode = fs::metadata(&path).expect("metadata").mode() & 0o777;
            assert_eq!(mode, 0o600, "owner-only permissions");
        }
        // A second unforced write refuses to overwrite.
        assert!(matches!(
            write_seed(&path, &seed(0x22), false, &rng),
            Err(KeyFileError::Exists(_))
        ));
        assert_eq!(read_seed(&path).expect("readable").bytes(), &[0x11; 32]);
        // A forced write replaces the contents and keeps owner-only mode.
        write_seed(&path, &seed(0x22), true, &rng).expect("forced write");
        assert_eq!(read_seed(&path).expect("readable").bytes(), &[0x22; 32]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let mode = fs::metadata(&path).expect("metadata").mode() & 0o777;
            assert_eq!(mode, 0o600, "replacement stays owner-only");
        }
        // No temporary file is left behind.
        let leftovers = fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains("tmp"))
            .count();
        assert_eq!(leftovers, 0);
    }

    #[cfg(unix)]
    #[test]
    fn impl_7_4_group_or_other_readable_seed_files_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir();
        let path = dir.path().join("root.seed");
        let rng = DeterministicRandom::from_seed(7);
        write_seed(&path, &seed(0x11), false, &rng).expect("write");
        for mode in [0o640, 0o604, 0o644, 0o666] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod");
            assert!(
                matches!(read_seed(&path), Err(KeyFileError::UnsafePermissions(_))),
                "mode {mode:o} must be refused"
            );
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).expect("chmod");
        assert!(read_seed(&path).is_ok(), "read-only owner mode is safe");
    }

    #[cfg(unix)]
    #[test]
    fn impl_7_4_symlinked_and_non_regular_paths_are_refused() {
        let dir = temp_dir();
        let real = dir.path().join("real.seed");
        let rng = DeterministicRandom::from_seed(7);
        write_seed(&real, &seed(0x11), false, &rng).expect("write");
        let link = dir.path().join("link.seed");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert!(matches!(read_seed(&link), Err(KeyFileError::NotRegular(_))));
        assert!(matches!(
            read_seed(dir.path()),
            Err(KeyFileError::NotRegular(_))
        ));
    }

    #[test]
    fn impl_7_4_malformed_files_are_refused_without_echoing_contents() {
        let dir = temp_dir();
        for (name, content) in [
            ("empty", ""),
            ("short", "followee-seed-v1:00ff"),
            ("odd", "followee-seed-v1:zz"),
            ("untagged", "a".repeat(64).as_str()),
            ("secretish", "followee-seed-v2:deadbeef"),
        ] {
            let path = dir.path().join(name);
            fs::write(&path, content).expect("write");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
            }
            let error = read_seed(&path).expect_err("refused");
            assert!(matches!(error, KeyFileError::Malformed(_)), "{name}");
            let rendered = error.to_string();
            assert!(
                !rendered.contains("deadbeef") && !rendered.contains("aaaa"),
                "error must not echo file contents: {rendered}"
            );
        }
    }

    #[test]
    fn impl_7_4_every_published_appendix_b_seed_is_refused() {
        let dir = temp_dir();
        let rng = DeterministicRandom::from_seed(7);
        for (index, seed_hex) in PUBLISHED_SEEDS.iter().enumerate() {
            let path = dir.path().join(format!("published-{index}"));
            let bytes: [u8; 32] = hex::decode(seed_hex)
                .expect("valid hex")
                .try_into()
                .expect("32 bytes");
            write_seed(&path, &SecretSeed::new(bytes), false, &rng).expect("write");
            assert!(
                matches!(read_seed(&path), Err(KeyFileError::PublishedTestSeed(_))),
                "published seed {index} must be refused"
            );
        }
    }

    #[test]
    fn secret_seed_debug_is_redacted() {
        let secret = seed(0xAB);
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "SecretSeed(redacted)");
        assert!(!rendered.contains("ab"));
    }
}
