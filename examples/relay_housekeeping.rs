//! Operator housekeeping tool for local demonstrations and tests: seeds a
//! relay directory and performs the section 11.3 Full-to-Ref storage
//! conversion on a relay's SQLite database, through the production store
//! contract only ([`RelayStore::set_directory`] and
//! [`RelayStore::convert_to_ref`]).
//!
//! These are relay-local storage decisions an operator makes (eviction
//! policy, directory curation) — not wire-protocol operations — so they are
//! not part of the `followee` binary's protocol command surface. No
//! protocol rule is implemented here: authority state, ordering metadata,
//! and `lastUpdated` preservation live in the store contract itself.
//!
//! Usage:
//!
//! ```text
//! relay_housekeeping set-directory  <db> <index> <relay-id-hex32> <endpoint>
//! relay_housekeeping convert-to-ref <db> <did> <index>
//! ```

use followee::random::{OsRandom, RandomSource};
use followee::store::sqlite::SqliteStore;
use followee::store::{DirectoryEntry, RelayIdentity, RelayStore};
use std::path::Path;

fn fail(message: &str) -> ! {
    eprintln!("relay_housekeeping: {message}");
    std::process::exit(2);
}

fn open_store(path: &str) -> SqliteStore {
    let identity = RelayIdentity::generate(&OsRandom)
        .unwrap_or_else(|e| fail(&format!("randomness failure: {e}")));
    SqliteStore::open(Path::new(path), identity)
        .unwrap_or_else(|e| fail(&format!("cannot open {path}: {e}")))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("set-directory") => {
            let [_, db, index, relay_id_hex, endpoint] = args.as_slice() else {
                fail("usage: set-directory <db> <index> <relay-id-hex32> <endpoint>");
            };
            let index: u32 = index.parse().unwrap_or_else(|_| fail("index must be u32"));
            let relay_id: [u8; 16] = hex::decode(relay_id_hex)
                .ok()
                .and_then(|v| v.try_into().ok())
                .unwrap_or_else(|| fail("relay id must be 16 hex bytes"));
            let mut store = open_store(db);
            // A directory mapping change requires a freshly generated random
            // generation value (specification section 11.4).
            let mut generation = [0u8; 16];
            OsRandom
                .fill(&mut generation)
                .unwrap_or_else(|e| fail(&format!("randomness failure: {e}")));
            store
                .set_directory(
                    vec![DirectoryEntry {
                        index,
                        relay_id,
                        endpoint: endpoint.clone(),
                        capabilities: 0x01 | 0x02 | 0x04,
                    }],
                    generation,
                )
                .unwrap_or_else(|e| fail(&format!("set_directory failed: {e}")));
            println!(
                "{{\"directoryGeneration\":\"{}\"}}",
                hex::encode(generation)
            );
        }
        Some("convert-to-ref") => {
            let [_, db, did, index] = args.as_slice() else {
                fail("usage: convert-to-ref <db> <did> <index>");
            };
            let index: u32 = index.parse().unwrap_or_else(|_| fail("index must be u32"));
            let mut store = open_store(db);
            let converted = store
                .convert_to_ref(did, index)
                .unwrap_or_else(|e| fail(&format!("convert_to_ref failed: {e}")));
            if !converted {
                fail("no entry for that DID");
            }
            println!("{{\"converted\":true}}");
        }
        _ => fail("usage: set-directory | convert-to-ref"),
    }
}
