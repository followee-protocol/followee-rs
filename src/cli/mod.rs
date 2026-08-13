//! `followee` command-line client: authoring, inspection, and selection
//! (IMPLEMENTATION.md sections 7.4, 7.5, 8, and 13 Milestone 2).
//!
//! Every protocol operation delegates to the reviewed production core —
//! [`crate::record::sign_record`], [`crate::verify::verify_record_for_target`],
//! [`crate::ordering::select_current`], [`crate::timestamp`] — and no
//! protocol, CBOR, signing, verification, ordering, or authority logic is
//! reimplemented here. Time and randomness are injected ([`Clock`],
//! [`RandomSource`]); the binary supplies the operating-system
//! implementations and tests supply deterministic ones.
//!
//! Commands are non-interactive, write one machine-readable JSON object to
//! stdout, return a non-zero exit status on failure with a stable symbolic
//! error name, and never place secret material in command lines, output,
//! diagnostics, errors, or panics.

mod handle;
pub mod json;
pub mod keyfile;
mod network;

use crate::clock::Clock;
use crate::did::FolloweeDid;
use crate::error::VerifyError;
use crate::limits::MAX_RECORD_BYTES;
use crate::ordering::{AuthorityState, select_current};
use crate::random::RandomSource;
use crate::record::{Authority, AuthorityDescriptor, RecordBody, SignError, sign_record};
use crate::timestamp::{Freshness, TimeStatus, freshness, next_timestamp, time_status};
use crate::verify::{VerifiedRecord, verify_record_for_target};
use clap::{Args, Parser, Subcommand};
use keyfile::{KeyFileError, read_seed, write_seed};
use serde_json::{Map, Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};

/// The demonstration-custody warning (IMPLEMENTATION.md section 7.4),
/// printed prominently and recorded in the identity file.
pub const CUSTODY_WARNING: &str = "seed files are demonstration custody, not a production \
     vault: anyone who reads them controls the identity permanently";

/// Root-revocation clock-sanity floor (specification section 5.3): the
/// signer refuses to proceed when its clock reads before 2020-01-01, which
/// can only mean a broken clock for this protocol's lifetime.
const CLOCK_SANITY_FLOOR_MS: u64 = 1_577_836_800_000;

/// CLI failure with a stable symbolic name. No variant carries secret
/// material, so no rendering path can reveal it.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Command-line usage error (exit status 2).
    #[error("{0}")]
    Usage(String),
    /// Secret-key storage failure.
    #[error(transparent)]
    Key(#[from] KeyFileError),
    /// Authoring JSON failure.
    #[error(transparent)]
    ContactJson(#[from] json::ContactJsonError),
    /// The identity file is missing a field or does not parse.
    #[error("identity file {0}: {1}")]
    IdentityFile(PathBuf, String),
    /// The supplied seed does not correspond to the identity's applicable
    /// public key or commitment.
    #[error("{0}")]
    KeyMismatch(&'static str),
    /// Record verification failed with the protocol classification.
    #[error("record verification failed: {0}")]
    Verify(#[from] VerifyError),
    /// Signing was refused by the core authoring path.
    #[error("signing refused: {0}")]
    Sign(SignError),
    /// The clock failed its sanity check for a revocation signature.
    #[error("clock sanity check failed: {0}")]
    ClockSanity(String),
    /// Timestamp arithmetic failed.
    #[error("timestamp selection failed: {0}")]
    Timestamp(#[from] crate::timestamp::TimestampError),
    /// The output file exists and `--force` was not given.
    #[error("refusing to overwrite existing file {0} without --force")]
    OutputExists(PathBuf),
    /// Filesystem failure on a non-secret path.
    #[error("{path}: {source}")]
    Io {
        /// The path involved.
        path: PathBuf,
        /// The operating-system error.
        source: std::io::Error,
    },
    /// The injected clock or randomness source failed.
    #[error("environment failure: {0}")]
    Environment(String),
    /// The production relay client failed; the layer that failed (policy,
    /// transport, HTTP status, rejected outer response, budget) is
    /// preserved in the symbol.
    #[error("relay client failure: {0}")]
    Client(#[from] crate::relay::client::ClientError),
    /// The synchronization receiver failed.
    #[error("synchronization failed: {0}")]
    Sync(#[from] crate::relay::sync::SyncError),
    /// The relay rejected the published record: a protocol rejection,
    /// distinct from transport or local infrastructure failure.
    #[error("relay rejected the record{0}")]
    PublishRejected(String),
    /// The resolution operation completed without a winning record. The
    /// complete machine-readable resolution is carried alongside the
    /// symbolic failure.
    #[error("resolution failed: {symbol}")]
    ResolutionFailed {
        /// `notFound` or `temporarilyUnavailable` (specification
        /// section 15.5).
        symbol: &'static str,
        /// The complete resolution result object.
        detail: Box<Value>,
    },
    /// The production WebFinger client failed; the layer that failed
    /// (handle form, policy, transport, HTTP, JRD parse, mapping
    /// requirement) is preserved in the symbol.
    #[error("webfinger failure: {0}")]
    WebFinger(#[from] crate::webfinger::WebFingerError),
    /// The handle-verification operation completed and the handle is not
    /// verified for the record. The complete machine-readable result is
    /// carried alongside the symbolic failure.
    #[error("the handle is not verified for this record")]
    HandleUnverified {
        /// The complete handle-verification result object.
        detail: Box<Value>,
    },
    /// The handle-authority configuration failed validation.
    #[error("authority configuration: {0}")]
    AuthorityConfig(#[from] crate::webfinger::authority::ConfigError),
    /// The predeployment consistency check completed and the
    /// configuration is not deployable: a served bootstrap record does
    /// not claim the exact handle it would be served for. The complete
    /// machine-readable report is carried alongside the symbolic failure.
    #[error("the configuration is not consistent for public deployment")]
    DeploymentInconsistent {
        /// The complete consistency report object.
        detail: Box<Value>,
    },
}

impl CliError {
    /// The stable symbolic error name for machine consumption.
    #[must_use]
    pub fn symbol(&self) -> &'static str {
        match self {
            CliError::Usage(_) => "usage",
            CliError::Key(e) => match e {
                KeyFileError::Exists(_) => "keyFileExists",
                KeyFileError::NotRegular(_) => "keyFileNotRegular",
                KeyFileError::UnsafePermissions(_) => "unsafeKeyFilePermissions",
                KeyFileError::Malformed(_) => "malformedKeyFile",
                KeyFileError::PublishedTestSeed(_) => "publishedTestSeed",
                KeyFileError::Io { .. } => "io",
            },
            CliError::ContactJson(_) => "contactJson",
            CliError::IdentityFile(..) => "identityFile",
            CliError::KeyMismatch(_) => "keyMismatch",
            CliError::Verify(e) => e.symbol(),
            CliError::Sign(e) => match e {
                SignError::InvalidBody(inner) => inner.symbol(),
                SignError::KeyMismatch => "keyMismatch",
                SignError::RecordTooLarge => "recordTooLarge",
            },
            CliError::ClockSanity(_) => "clockSanity",
            CliError::Timestamp(_) => "timestampOverflow",
            CliError::OutputExists(_) => "outputExists",
            CliError::Io { .. } => "io",
            CliError::Environment(_) => "environment",
            CliError::Client(e) => e.symbol(),
            CliError::Sync(e) => e.symbol(),
            CliError::PublishRejected(_) => "publishRejected",
            CliError::ResolutionFailed { symbol, .. } => symbol,
            CliError::WebFinger(e) => e.symbol(),
            CliError::HandleUnverified { .. } => "handleUnverified",
            CliError::AuthorityConfig(_) => "authorityConfig",
            CliError::DeploymentInconsistent { .. } => "deploymentInconsistent",
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "followee",
    about = "Non-normative Followee DID authoring and inspection client",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: TopCommand,
}

#[derive(Subcommand, Debug)]
enum TopCommand {
    /// Identity operations.
    #[command(subcommand)]
    Identity(IdentityCommand),
    /// Record operations.
    #[command(subcommand)]
    Record(RecordCommand),
    /// Relay operations.
    #[command(subcommand)]
    Relay(RelayCommand),
    /// Resolve a DID through the multi-relay production resolver.
    Resolve(ResolveArgs),
    /// Handle discovery, verification, and the demonstration authority.
    #[command(subcommand)]
    Handle(HandleCommand),
}

#[derive(Subcommand, Debug)]
enum HandleCommand {
    /// Discover the Followee DID mapped to a handle through the production
    /// WebFinger client, with optional current-record bootstrap.
    Resolve(HandleResolveArgs),
    /// Verify a handle claim: local record verification combined with
    /// inverse WebFinger discovery binding the same DID.
    Verify(HandleVerifyArgs),
    /// Run the minimal demonstration handle authority.
    Serve(HandleServeArgs),
}

#[derive(Subcommand, Debug)]
enum RelayCommand {
    /// Run the single bounded relay over a SQLite database.
    Serve(ServeArgs),
    /// Publish one complete Identity Record to a relay.
    Publish(RelayPublishArgs),
    /// Resolve DIDs directly against one relay.
    Resolve(RelayResolveArgs),
    /// Fetch one page of a relay's current-state changes feed.
    Changes(RelayChangesArgs),
    /// Run one explicit synchronization pass from a peer's changes feed
    /// into a local relay database.
    Sync(RelaySyncArgs),
}

/// Explicit network policy selection (IMPLEMENTATION.md section 9.5).
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyArg {
    /// Default public policy: HTTPS to public destinations only.
    Public,
    /// Explicitly non-conforming loopback development policy.
    Development,
}

impl PolicyArg {
    fn policy(self) -> crate::relay::client::NetworkPolicy {
        match self {
            PolicyArg::Public => crate::relay::client::NetworkPolicy::Public,
            PolicyArg::Development => crate::relay::client::NetworkPolicy::Development,
        }
    }
}

#[derive(Subcommand, Debug)]
enum IdentityCommand {
    /// Create a new Followee identity: two independent key files and a
    /// public identity file.
    Create(CreateArgs),
}

#[derive(Subcommand, Debug)]
enum RecordCommand {
    /// Sign a complete Root Identity Record.
    SignRoot(SignArgs),
    /// Sign a complete RootRevoked Identity Record with the separately
    /// stored revocation key.
    RevokeRoot(SignArgs),
    /// Verify a complete record against a target DID.
    Verify(VerifyArgs),
    /// Inspect a record, distinguishing raw claims from verified facts.
    Inspect(InspectArgs),
    /// Deterministically select the winning record for a target DID.
    Select(SelectArgs),
}

#[derive(Args, Debug)]
struct CreateArgs {
    /// Path for the new root seed file (owner-only).
    #[arg(long)]
    root_key: PathBuf,
    /// Path for the new revocation seed file (owner-only; may point at
    /// separate or removable media).
    #[arg(long)]
    revocation_key: PathBuf,
    /// Path for the public identity file (DID, root public key, commitment).
    #[arg(long)]
    identity: PathBuf,
    /// Overwrite existing files.
    #[arg(long)]
    force: bool,
}

#[derive(Args, Debug)]
struct SignArgs {
    /// The public identity file written by `identity create`.
    #[arg(long)]
    identity: PathBuf,
    /// The seed file for the applicable authority state (root key for
    /// sign-root, revocation key for revoke-root).
    #[arg(long)]
    key: PathBuf,
    /// The complete Contact Document as authoring JSON.
    #[arg(long)]
    contact: PathBuf,
    /// Output path for the complete COSE record.
    #[arg(long)]
    out: PathBuf,
    /// Explicit ordering timestamp; default max(now, previous + 1).
    #[arg(long)]
    timestamp_ms: Option<u64>,
    /// Greatest non-premature timestamp already known for this DID.
    #[arg(long)]
    previous_timestamp_ms: Option<u64>,
    /// Optional freshness horizon.
    #[arg(long)]
    valid_until_ms: Option<u64>,
    /// Overwrite an existing output file.
    #[arg(long)]
    force: bool,
}

#[derive(Args, Debug)]
struct VerifyArgs {
    /// The expected target DID.
    #[arg(long)]
    did: String,
    /// The complete COSE record file.
    #[arg(long)]
    record: PathBuf,
    /// Recipient time override for deterministic classification.
    #[arg(long)]
    now_ms: Option<u64>,
}

#[derive(Args, Debug)]
struct InspectArgs {
    /// The complete COSE record file.
    #[arg(long)]
    record: PathBuf,
    /// Verify against this target DID; without it the output is raw,
    /// unverified claims only.
    #[arg(long)]
    did: Option<String>,
    /// Recipient time override for deterministic classification.
    #[arg(long)]
    now_ms: Option<u64>,
}

#[derive(Args, Debug)]
struct SelectArgs {
    /// The explicit target DID; candidates never choose the subject.
    #[arg(long)]
    did: String,
    /// Recipient time override for deterministic classification.
    #[arg(long)]
    now_ms: Option<u64>,
    /// Model retained sticky RootRevoked state for the target.
    #[arg(long)]
    assume_root_revoked: bool,
    /// Candidate record files, in any order.
    #[arg(required = true)]
    records: Vec<PathBuf>,
}

#[derive(Args, Debug)]
struct RelayPublishArgs {
    /// The relay base URI, ending in `/`.
    #[arg(long)]
    relay: String,
    /// The complete COSE record file to publish.
    #[arg(long)]
    record: PathBuf,
    /// Network policy for the connection.
    #[arg(long, value_enum, default_value_t = PolicyArg::Public)]
    policy: PolicyArg,
    /// Per-request timeout in milliseconds.
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,
}

#[derive(Args, Debug)]
struct RelayResolveArgs {
    /// The relay base URI, ending in `/`.
    #[arg(long)]
    relay: String,
    /// Requested DIDs, order and duplicates preserved exactly.
    #[arg(long = "did", required = true)]
    dids: Vec<String>,
    /// Network policy for the connection.
    #[arg(long, value_enum, default_value_t = PolicyArg::Public)]
    policy: PolicyArg,
    /// Per-request timeout in milliseconds.
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,
    /// Recipient time override for deterministic classification.
    #[arg(long)]
    now_ms: Option<u64>,
}

#[derive(Args, Debug)]
struct RelayChangesArgs {
    /// The relay base URI, ending in `/`.
    #[arg(long)]
    relay: String,
    /// Opaque cursor bytes as hex; omitted for an initial enumeration.
    #[arg(long)]
    cursor: Option<String>,
    /// Requested `itemLimit` (1..=1024).
    #[arg(long, default_value_t = 256)]
    item_limit: u64,
    /// Requested `byteLimit` (1..=4194304).
    #[arg(long, default_value_t = 1_048_576)]
    byte_limit: u64,
    /// Network policy for the connection.
    #[arg(long, value_enum, default_value_t = PolicyArg::Public)]
    policy: PolicyArg,
    /// Per-request timeout in milliseconds.
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,
}

#[derive(Args, Debug)]
struct RelaySyncArgs {
    /// The local relay SQLite database to synchronize into.
    #[arg(long)]
    database: PathBuf,
    /// The peer relay base URI, ending in `/`.
    #[arg(long)]
    peer: String,
    /// Network policy for the connection.
    #[arg(long, value_enum, default_value_t = PolicyArg::Public)]
    policy: PolicyArg,
    /// `itemLimit` per changes request (1..=1024).
    #[arg(long, default_value_t = 256)]
    item_limit: u64,
    /// `byteLimit` per changes request (1..=4194304).
    #[arg(long, default_value_t = 1_048_576)]
    byte_limit: u64,
    /// Maximum feed pages fetched in this pass.
    #[arg(long, default_value_t = 16)]
    max_pages: u32,
    /// Per-request timeout in milliseconds.
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,
    /// Receiver time override for deterministic admission classification.
    #[arg(long)]
    now_ms: Option<u64>,
}

#[derive(Args, Debug)]
struct ResolveArgs {
    /// The target DID to resolve.
    #[arg(long)]
    did: String,
    /// Configured relay base URIs, queried in order.
    #[arg(long = "relay", required = true)]
    relays: Vec<String>,
    /// Network policy for connections.
    #[arg(long, value_enum, default_value_t = PolicyArg::Public)]
    policy: PolicyArg,
    /// Optional client-state file: sticky authority state, cached verified
    /// records, and routing hints persist across invocations.
    #[arg(long)]
    state: Option<PathBuf>,
    /// Recipient time override for deterministic classification.
    #[arg(long)]
    now_ms: Option<u64>,
    /// Resolution deadline duration in milliseconds.
    #[arg(long, default_value_t = 10_000)]
    deadline_ms: u64,
    /// Check the winning record's migration claims reciprocally through
    /// the same shared operation budgets, reporting one of the three
    /// section 14.2 states per claim. Never re-follows automatically.
    #[arg(long)]
    check_migration: bool,
}

#[derive(Args, Debug)]
struct ServeArgs {
    /// SQLite database path; created on first use, reopened thereafter.
    #[arg(long)]
    database: PathBuf,
    /// Listen address. Loopback by default; port 0 assigns an ephemeral
    /// port, reported in the startup object.
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: String,
    /// Advertised canonical base URI ending in `/`. An HTTPS URI selects
    /// conforming mode (for operation behind a TLS reverse proxy); when
    /// omitted the relay runs in explicitly non-conforming development mode
    /// with the bound loopback address.
    #[arg(long)]
    base_uri: Option<String>,
}

#[derive(Args, Debug)]
struct HandleResolveArgs {
    /// The handle, local@domain.
    #[arg(long)]
    handle: String,
    /// Network policy for connections.
    #[arg(long, value_enum, default_value_t = PolicyArg::Public)]
    policy: PolicyArg,
    /// Explicit authority endpoint base ending in '/', for loopback tests
    /// under the development policy only; public lookups always derive the
    /// endpoint from the handle domain.
    #[arg(long)]
    endpoint: Option<String>,
    /// Do not fetch bootstrap record links.
    #[arg(long)]
    no_bootstrap: bool,
    /// Optional client-state file: sticky authority state and cached
    /// verified records persist across invocations.
    #[arg(long)]
    state: Option<PathBuf>,
    /// Recipient time override for deterministic classification.
    #[arg(long)]
    now_ms: Option<u64>,
    /// Per-request timeout in milliseconds.
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,
}

#[derive(Args, Debug)]
struct HandleVerifyArgs {
    /// The handle, local@domain.
    #[arg(long)]
    handle: String,
    /// The expected Followee DID: the durable identity key the follower
    /// already holds. Discovery never chooses it.
    #[arg(long)]
    did: String,
    /// A local complete COSE record file to verify (offline record source).
    #[arg(long)]
    record: Option<PathBuf>,
    /// Relay base URIs to resolve the record through (network record
    /// source); repeatable.
    #[arg(long = "relay")]
    relays: Vec<String>,
    /// Network policy for connections.
    #[arg(long, value_enum, default_value_t = PolicyArg::Public)]
    policy: PolicyArg,
    /// Explicit authority endpoint base ending in '/', for loopback tests
    /// under the development policy only.
    #[arg(long)]
    endpoint: Option<String>,
    /// Optional client-state file.
    #[arg(long)]
    state: Option<PathBuf>,
    /// Recipient time override for deterministic classification.
    #[arg(long)]
    now_ms: Option<u64>,
    /// Per-request timeout in milliseconds.
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,
    /// Operation deadline duration in milliseconds.
    #[arg(long, default_value_t = 10_000)]
    deadline_ms: u64,
}

#[derive(Args, Debug)]
struct HandleServeArgs {
    /// The authority configuration JSON file.
    #[arg(long)]
    config: PathBuf,
    /// Listen address. Loopback by default; port 0 assigns an ephemeral
    /// port, reported in the startup object.
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: String,
    /// Advertised canonical base URI ending in `/`. An HTTPS URI selects
    /// conforming mode (for operation behind provider TLS termination);
    /// when omitted the authority runs in explicitly non-conforming
    /// development mode with the bound loopback address.
    #[arg(long)]
    base_uri: Option<String>,
    /// Run the predeployment consistency check instead of serving:
    /// validate the configuration completely, require every local served
    /// with a bootstrap record to be exactly claimed by that record, and
    /// exit nonzero on any mismatch.
    #[arg(long)]
    check: bool,
}

/// Runs the CLI with injected environment and output streams, returning the
/// process exit status: `0` success, `1` operation failure, `2` usage error.
pub fn run(
    args: &[String],
    rng: &dyn RandomSource,
    clock: &dyn Clock,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let mut argv = vec!["followee".to_owned()];
    argv.extend_from_slice(args);
    let cli = match Cli::try_parse_from(&argv) {
        Ok(cli) => cli,
        Err(e) => {
            // Help/version renderings are successful outputs.
            return if e.use_stderr() {
                let _ = write!(stderr, "{e}");
                2
            } else {
                let _ = write!(stdout, "{e}");
                0
            };
        }
    };
    match dispatch(cli.command, rng, clock, stdout, stderr) {
        Ok(Some(output)) => {
            let _ = writeln!(stdout, "{output}");
            0
        }
        // The command wrote its own protocol-defined stdout (relay serve's
        // startup object) and finished cleanly.
        Ok(None) => 0,
        Err(error) => {
            let mut payload = json!({
                "error": { "symbol": error.symbol(), "message": error.to_string() }
            });
            // A completed-but-unsuccessful resolution still emits its one
            // complete machine-readable result alongside the symbol.
            if let CliError::ResolutionFailed { detail, .. } = &error {
                if let Some(object) = payload.as_object_mut() {
                    object.insert("resolution".to_owned(), (**detail).clone());
                }
            }
            // Likewise a completed-but-unverified handle check.
            if let CliError::HandleUnverified { detail } = &error {
                if let Some(object) = payload.as_object_mut() {
                    object.insert("handleVerification".to_owned(), (**detail).clone());
                }
            }
            // And a completed-but-failed deployment consistency check.
            if let CliError::DeploymentInconsistent { detail } = &error {
                if let Some(object) = payload.as_object_mut() {
                    object.insert("consistency".to_owned(), (**detail).clone());
                }
            }
            let _ = writeln!(stdout, "{payload}");
            let _ = writeln!(stderr, "error[{}]: {error}", error.symbol());
            if matches!(error, CliError::Usage(_)) {
                2
            } else {
                1
            }
        }
    }
}

fn dispatch(
    command: TopCommand,
    rng: &dyn RandomSource,
    clock: &dyn Clock,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<Option<Value>, CliError> {
    match command {
        TopCommand::Identity(IdentityCommand::Create(args)) => {
            identity_create(&args, rng, stderr).map(Some)
        }
        TopCommand::Record(RecordCommand::SignRoot(args)) => {
            sign(&args, Authority::Root, clock).map(Some)
        }
        TopCommand::Record(RecordCommand::RevokeRoot(args)) => {
            sign(&args, Authority::RootRevoked, clock).map(Some)
        }
        TopCommand::Record(RecordCommand::Verify(args)) => verify(&args, clock).map(Some),
        TopCommand::Record(RecordCommand::Inspect(args)) => inspect(&args, clock).map(Some),
        TopCommand::Record(RecordCommand::Select(args)) => select(&args, clock).map(Some),
        TopCommand::Relay(RelayCommand::Serve(args)) => relay_serve(&args, rng, stdout, stderr),
        TopCommand::Relay(RelayCommand::Publish(args)) => {
            network::relay_publish(&args, clock).map(Some)
        }
        TopCommand::Relay(RelayCommand::Resolve(args)) => {
            network::relay_resolve(&args, clock).map(Some)
        }
        TopCommand::Relay(RelayCommand::Changes(args)) => {
            network::relay_changes(&args, clock).map(Some)
        }
        TopCommand::Relay(RelayCommand::Sync(args)) => network::relay_sync(&args, rng).map(Some),
        TopCommand::Resolve(args) => network::resolve_multi(&args, clock).map(Some),
        TopCommand::Handle(HandleCommand::Resolve(args)) => {
            handle::handle_resolve(&args, clock).map(Some)
        }
        TopCommand::Handle(HandleCommand::Verify(args)) => {
            handle::handle_verify(&args, clock).map(Some)
        }
        TopCommand::Handle(HandleCommand::Serve(args)) => {
            handle::handle_serve(&args, stdout, stderr)
        }
    }
}

// ---------------------------------------------------------------------------
// relay serve
// ---------------------------------------------------------------------------

/// Runs the production relay HTTP server over a SQLite store until an
/// interrupt or termination signal arrives.
///
/// The startup object is the command's one protocol-defined stdout line;
/// everything afterwards — the non-conforming development-mode notice and
/// the shutdown message — is stderr diagnostics. The relay itself uses the
/// operating-system clock ([`crate::clock::SystemClock`]); the injected
/// `rng` supplies the identity generated on first database creation.
fn relay_serve(
    args: &ServeArgs,
    rng: &dyn RandomSource,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<Option<Value>, CliError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::Environment(e.to_string()))?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(&args.listen)
            .await
            .map_err(|source| CliError::Io {
                path: PathBuf::from(&args.listen),
                source,
            })?;
        let bound = listener
            .local_addr()
            .map_err(|e| CliError::Environment(e.to_string()))?;
        let (base_uri, development_mode) = match &args.base_uri {
            Some(uri) => (uri.clone(), !uri.starts_with("https://")),
            None => (format!("http://{bound}/"), true),
        };

        // A fresh identity is generated from the injected randomness only
        // when the database is new; reopening keeps the persisted identity.
        let fresh = crate::store::RelayIdentity::generate(rng)
            .map_err(|e| CliError::Environment(e.to_string()))?;
        let store = crate::store::sqlite::SqliteStore::open(&args.database, fresh)
            .map_err(|e| CliError::Environment(e.to_string()))?;
        let identity = {
            use crate::store::RelayStore;
            store
                .identity()
                .map_err(|e| CliError::Environment(e.to_string()))?
        };
        let relay = crate::relay::Relay::new(
            Box::new(store),
            Box::new(crate::clock::SystemClock),
            crate::relay::RelayConfig {
                base_uri: base_uri.clone(),
                development_mode,
            },
        )
        .map_err(|e| CliError::Usage(e.to_string()))?;

        // The shutdown listener exists before readiness is advertised, so
        // a signal racing the startup object still shuts down cleanly.
        let shutdown = shutdown_signal();
        // The one machine-readable startup object; stdout carries nothing
        // else. Secret material never exists in this command.
        let startup = json!({
            "listen": bound.to_string(),
            "baseUri": base_uri,
            "database": args.database.display().to_string(),
            "developmentMode": development_mode,
            "relayId": hex::encode(identity.relay_id),
            "cursorGeneration": hex::encode(identity.cursor_generation),
            "directoryGeneration": hex::encode(identity.directory_generation),
        });
        let _ = writeln!(stdout, "{startup}");
        let _ = stdout.flush();
        if development_mode {
            let _ = writeln!(
                stderr,
                "WARNING: development mode is explicitly non-conforming: plain \
                 HTTP on a loopback address only. Conforming public operation \
                 requires an HTTPS base URI behind TLS."
            );
        }

        crate::relay::http::serve_with_shutdown(std::sync::Arc::new(relay), listener, shutdown)
            .await
            .map_err(|e| CliError::Environment(e.to_string()))?;
        let _ = writeln!(stderr, "relay stopped");
        Ok(None)
    })
}

/// Returns a future that resolves on Ctrl-C, or on SIGTERM where the
/// platform delivers it. The SIGTERM listener is registered at call time
/// — callers construct this before writing their startup object — so a
/// signal arriving immediately after startup is advertised still produces
/// the clean shutdown path rather than the default termination.
fn shutdown_signal() -> impl std::future::Future<Output = ()> + Send + 'static {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM handler installs");
        async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
        }
    }
    #[cfg(not(unix))]
    {
        async {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

// ---------------------------------------------------------------------------
// identity create
// ---------------------------------------------------------------------------

fn identity_create(
    args: &CreateArgs,
    rng: &dyn RandomSource,
    stderr: &mut dyn Write,
) -> Result<Value, CliError> {
    if args.root_key == args.revocation_key {
        return Err(CliError::Usage(
            "root and revocation secrets must be written to separately named files".to_owned(),
        ));
    }
    let root_seed = generate_seed(rng)?;
    let revocation_seed = generate_seed(rng)?;

    // Specification section 4.4 step 2: validate both public keys under
    // section 3.3 through the production strict verifier.
    let root_public = crate::crypto::ed25519_public_key(root_seed.bytes());
    let revocation_public = crate::crypto::ed25519_public_key(revocation_seed.bytes());
    for (seed, public) in [
        (&root_seed, &root_public),
        (&revocation_seed, &revocation_public),
    ] {
        let probe = crate::crypto::ed25519_sign(seed.bytes(), b"followee key self-check");
        if !crate::crypto::verify_followee_ed25519(public, b"followee key self-check", &probe) {
            return Err(CliError::Environment(
                "generated key failed its strict self-check".to_owned(),
            ));
        }
    }

    let descriptor = AuthorityDescriptor {
        root_key: root_public,
        revocation_commitment: crate::record::revocation_commitment(&revocation_public),
    };
    let did = descriptor.did();

    // Secrets first, then the public identity file naming them.
    write_seed(&args.root_key, &root_seed, args.force, rng)?;
    write_seed(&args.revocation_key, &revocation_seed, args.force, rng)?;
    let identity = json!({
        "did": did.as_str(),
        "rootPublicKey": hex::encode(descriptor.root_key),
        "revocationCommitment": hex::encode(descriptor.revocation_commitment),
        "custody": CUSTODY_WARNING,
    });
    write_public(
        &args.identity,
        format!("{identity}\n").as_bytes(),
        args.force,
    )?;

    let _ = writeln!(stderr, "WARNING: {CUSTODY_WARNING}");
    let _ = writeln!(
        stderr,
        "Store the revocation seed file under materially separate custody; \
         without it the DID has no recovery path."
    );
    Ok(json!({
        "did": did.as_str(),
        "identityFile": args.identity.display().to_string(),
        "rootKeyFile": args.root_key.display().to_string(),
        "revocationKeyFile": args.revocation_key.display().to_string(),
        "custody": CUSTODY_WARNING,
    }))
}

fn generate_seed(rng: &dyn RandomSource) -> Result<keyfile::SecretSeed, CliError> {
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes)
        .map_err(|e| CliError::Environment(e.to_string()))?;
    Ok(keyfile::SecretSeed::new(bytes))
}

// ---------------------------------------------------------------------------
// record sign-root / revoke-root
// ---------------------------------------------------------------------------

struct IdentityFile {
    did: FolloweeDid,
    descriptor: AuthorityDescriptor,
}

fn read_identity(path: &Path) -> Result<IdentityFile, CliError> {
    let fail = |message: String| CliError::IdentityFile(path.to_path_buf(), message);
    let text = std::fs::read_to_string(path).map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let value: Value =
        serde_json::from_str(&text).map_err(|e| fail(format!("not valid JSON: {e}")))?;
    let field = |name: &str| -> Result<String, CliError> {
        value
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| fail(format!("missing field {name:?}")))
    };
    let did = FolloweeDid::parse(&field("did")?).map_err(|e| fail(format!("did: {e}")))?;
    let root_key: [u8; 32] = hex::decode(field("rootPublicKey")?)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| fail("rootPublicKey must be 32 hex bytes".to_owned()))?;
    let revocation_commitment: [u8; 32] = hex::decode(field("revocationCommitment")?)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| fail("revocationCommitment must be 32 hex bytes".to_owned()))?;
    let descriptor = AuthorityDescriptor {
        root_key,
        revocation_commitment,
    };
    if descriptor.did() != did {
        return Err(fail(
            "descriptor does not reproduce the stated DID".to_owned(),
        ));
    }
    Ok(IdentityFile { did, descriptor })
}

fn sign(args: &SignArgs, authority: Authority, clock: &dyn Clock) -> Result<Value, CliError> {
    let identity = read_identity(&args.identity)?;
    let seed = read_seed(&args.key)?;
    let public = crate::crypto::ed25519_public_key(seed.bytes());

    let revocation_key = match authority {
        Authority::Root => {
            if public != identity.descriptor.root_key {
                return Err(CliError::KeyMismatch(
                    "the supplied seed is not this identity's root key",
                ));
            }
            None
        }
        Authority::RootRevoked => {
            // The revealed key must reproduce the descriptor commitment; a
            // wrong file fails here, before any signature exists.
            let commitment = crate::record::revocation_commitment(&public);
            if commitment != identity.descriptor.revocation_commitment {
                return Err(CliError::KeyMismatch(
                    "the supplied seed is not this identity's committed revocation key",
                ));
            }
            // Specification section 5.3: an explicit clock-sanity check
            // before signing a root revocation.
            let now = clock
                .now_ms()
                .map_err(|e| CliError::ClockSanity(e.to_string()))?;
            if now < CLOCK_SANITY_FLOOR_MS {
                return Err(CliError::ClockSanity(format!(
                    "clock reads {now} ms, before 2020-01-01; refusing to sign a revocation"
                )));
            }
            Some(public)
        }
    };

    let contact_text = std::fs::read_to_string(&args.contact).map_err(|source| CliError::Io {
        path: args.contact.clone(),
        source,
    })?;
    let contact = json::contact_from_json(&contact_text)?;

    let timestamp_ms = match args.timestamp_ms {
        Some(explicit) => explicit,
        None => {
            let now = clock
                .now_ms()
                .map_err(|e| CliError::Environment(e.to_string()))?;
            next_timestamp(now, args.previous_timestamp_ms)?
        }
    };

    let body = RecordBody {
        id: identity.did.clone(),
        timestamp_ms,
        authority,
        descriptor: identity.descriptor,
        revocation_key,
        valid_until_ms: args.valid_until_ms,
        contact,
        extensions: Default::default(),
    };
    // The core authoring path validates the complete schema, every limit,
    // and key applicability before any signature is produced.
    let envelope = sign_record(&body, seed.bytes()).map_err(CliError::Sign)?;
    write_public(&args.out, &envelope, args.force)?;

    Ok(json!({
        "did": identity.did.as_str(),
        "authority": authority_name(authority),
        "timestampMs": timestamp_ms,
        "bodyDigest": hex::encode(crate::crypto::sha256(
            &body.encode().map_err(CliError::Verify)?
        )),
        "recordFile": args.out.display().to_string(),
    }))
}

// ---------------------------------------------------------------------------
// record verify / inspect / select
// ---------------------------------------------------------------------------

fn read_record_bounded(path: &Path) -> Result<Vec<u8>, CliError> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    // Bounded before allocation: one byte past the cap is enough to let the
    // core classify recordTooLarge exactly.
    let mut bytes = Vec::new();
    let limit = (MAX_RECORD_BYTES as u64).saturating_add(1);
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(bytes)
}

fn now_for(clock: &dyn Clock, override_ms: Option<u64>) -> Result<u64, CliError> {
    match override_ms {
        Some(now) => Ok(now),
        None => clock
            .now_ms()
            .map_err(|e| CliError::Environment(e.to_string())),
    }
}

fn verified_facts(record: &VerifiedRecord, now_ms: u64) -> Value {
    json!({
        "did": record.body().id.as_str(),
        "authority": authority_name(record.authority()),
        "timestampMs": record.timestamp_ms(),
        "bodyDigest": hex::encode(record.body_digest()),
        "timeStatus": match time_status(record.timestamp_ms(), now_ms) {
            TimeStatus::Admissible => "admissible",
            TimeStatus::Premature => "premature",
        },
        "freshness": match freshness(record.body().valid_until_ms, now_ms) {
            Freshness::Fresh => "fresh",
            Freshness::Stale => "stale",
        },
    })
}

fn verify(args: &VerifyArgs, clock: &dyn Clock) -> Result<Value, CliError> {
    let bytes = read_record_bounded(&args.record)?;
    let record = verify_record_for_target(&args.did, &bytes)?;
    let now_ms = now_for(clock, args.now_ms)?;
    let mut output = verified_facts(&record, now_ms)
        .as_object()
        .cloned()
        .unwrap_or_default();
    output.insert("verified".to_owned(), Value::Bool(true));
    output.insert(
        "recordFile".to_owned(),
        Value::String(args.record.display().to_string()),
    );
    Ok(Value::Object(output))
}

fn inspect(args: &InspectArgs, clock: &dyn Clock) -> Result<Value, CliError> {
    let bytes = read_record_bounded(&args.record)?;
    // Raw claims come from the same crate parsers used by verification; a
    // record that cannot even parse is an inspection failure.
    let claims = raw_claims(&bytes)?;
    let verification = match &args.did {
        None => json!({
            "status": "unverified",
            "note": "raw signed claims only; no target DID was supplied and \
                     no signature, binding, or schema authority is implied",
        }),
        Some(did) => match verify_record_for_target(did, &bytes) {
            Ok(record) => {
                let now_ms = now_for(clock, args.now_ms)?;
                let mut facts = verified_facts(&record, now_ms)
                    .as_object()
                    .cloned()
                    .unwrap_or_default();
                facts.insert("status".to_owned(), Value::String("verified".to_owned()));
                Value::Object(facts)
            }
            Err(error) => json!({
                "status": "failed",
                "error": error.symbol(),
                "note": "the claims below are unverified",
            }),
        },
    };
    Ok(json!({
        "recordFile": args.record.display().to_string(),
        "verification": verification,
        "claims": claims,
    }))
}

/// Parses raw, unverified claims through the crate's own envelope and body
/// parsers (never a second implementation).
fn raw_claims(bytes: &[u8]) -> Result<Value, CliError> {
    let parts = crate::cose::parse_envelope(bytes).map_err(CliError::Verify)?;
    let payload = &bytes[parts.payload.clone()];
    crate::cbor::validate(
        payload,
        crate::limits::MAX_BODY_DEPTH,
        crate::limits::MAX_BODY_MEMBERS,
    )
    .map_err(|e| CliError::Verify(e.into()))?;
    let body = crate::record::parse_record_body(payload).map_err(CliError::Verify)?;
    let mut claims = Map::new();
    claims.insert("id".to_owned(), Value::String(body.id_text.clone()));
    claims.insert(
        "timestampMs".to_owned(),
        Value::Number(body.timestamp_ms.into()),
    );
    claims.insert(
        "authority".to_owned(),
        Value::String(authority_name(body.authority).to_owned()),
    );
    if let Some(valid_until) = body.valid_until_ms {
        claims.insert("validUntilMs".to_owned(), Value::Number(valid_until.into()));
    }
    claims.insert("contact".to_owned(), json::contact_to_json(&body.contact));
    Ok(Value::Object(claims))
}

fn select(args: &SelectArgs, clock: &dyn Clock) -> Result<Value, CliError> {
    // The target is explicit and parsed first: candidates cannot choose the
    // subject (IMPLEMENTATION.md section 7.1).
    let target = FolloweeDid::parse(&args.did).map_err(|e| CliError::Verify(e.into()))?;
    let now_ms = now_for(clock, args.now_ms)?;
    let sticky = if args.assume_root_revoked {
        AuthorityState::RootRevoked
    } else {
        AuthorityState::Unknown
    };

    let mut candidates: Vec<(usize, VerifiedRecord)> = Vec::new();
    let mut rejected = Vec::new();
    for (index, path) in args.records.iter().enumerate() {
        let bytes = read_record_bounded(path)?;
        match verify_record_for_target(target.as_str(), &bytes) {
            Ok(record) => candidates.push((index, record)),
            // Invalid candidates — including valid records for other DIDs —
            // are reported diagnostically and cannot influence selection.
            Err(error) => rejected.push(json!({
                "recordFile": path.display().to_string(),
                "error": error.symbol(),
            })),
        }
    }

    let verified: Vec<VerifiedRecord> = candidates
        .iter()
        .map(|(_, record)| record.clone())
        .collect();
    let selection = select_current(&target, &verified, now_ms, sticky);
    let winner = selection.winner.map(|winner| {
        let (index, _) = candidates
            .iter()
            .find(|(_, record)| record.body_digest() == winner.body_digest())
            .expect("winner came from the candidate list");
        json!({
            "recordFile": args.records[*index].display().to_string(),
            "authority": authority_name(winner.authority()),
            "timestampMs": winner.timestamp_ms(),
            "bodyDigest": hex::encode(winner.body_digest()),
        })
    });
    Ok(json!({
        "targetDid": target.as_str(),
        "authorityState": match selection.authority_state {
            AuthorityState::Unknown => "unknown",
            AuthorityState::Root => "root",
            AuthorityState::RootRevoked => "rootRevoked",
        },
        "winner": winner,
        "rejected": rejected,
    }))
}

fn authority_name(authority: Authority) -> &'static str {
    match authority {
        Authority::Root => "root",
        Authority::RootRevoked => "rootRevoked",
    }
}

/// Writes a non-secret output file: exclusive creation unless forced.
fn write_public(path: &Path, content: &[u8], force: bool) -> Result<(), CliError> {
    let result = if force {
        std::fs::write(path, content)
    } else {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .and_then(|mut file| file.write_all(content))
    };
    result.map_err(|source| {
        if source.kind() == std::io::ErrorKind::AlreadyExists {
            CliError::OutputExists(path.to_path_buf())
        } else {
            CliError::Io {
                path: path.to_path_buf(),
                source,
            }
        }
    })
}
