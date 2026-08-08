//! Opaque bounded cursor encoding (specification section 12.7).
//!
//! A cursor commits to the relay's current cursor generation and a
//! relay-local scan position. The encoding is relay-local and opaque to
//! clients: 16 generation bytes followed by the 8-byte big-endian position,
//! 24 bytes total, well under the 128-byte protocol cap.

/// Encoded cursor length in bytes.
pub(crate) const CURSOR_LEN: usize = 24;

/// Decoding outcome for a received cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CursorDecode {
    /// A cursor from the current generation, carrying its scan position.
    Position(u64),
    /// A structurally valid cursor from another generation: the client must
    /// discard it and re-enumerate (`ResetRequired`, status `1`).
    ForeignGeneration,
    /// Not a cursor this relay could ever have produced
    /// (`invalidCursor`, wire error 18).
    Malformed,
}

/// Encodes a cursor committing to `generation` and `position`.
pub(crate) fn encode(generation: &[u8; 16], position: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(CURSOR_LEN);
    out.extend_from_slice(generation);
    out.extend_from_slice(&position.to_be_bytes());
    out
}

/// Decodes a received cursor against the relay's current generation.
pub(crate) fn decode(bytes: &[u8], current_generation: &[u8; 16]) -> CursorDecode {
    if bytes.len() != CURSOR_LEN {
        return CursorDecode::Malformed;
    }
    let (generation, position) = bytes.split_at(16);
    if generation != current_generation {
        return CursorDecode::ForeignGeneration;
    }
    // The split guarantees exactly eight position bytes.
    let position: [u8; 8] = position.try_into().unwrap_or_default();
    CursorDecode::Position(u64::from_be_bytes(position))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GEN: [u8; 16] = [7; 16];

    #[test]
    fn sec_12_7_round_trips_within_the_current_generation() {
        for position in [0, 1, 41, u64::MAX] {
            let cursor = encode(&GEN, position);
            assert!(cursor.len() <= 128, "cursor stays within the 128-byte cap");
            assert_eq!(decode(&cursor, &GEN), CursorDecode::Position(position));
        }
    }

    #[test]
    fn sec_12_7_foreign_generation_requires_reset() {
        let cursor = encode(&GEN, 7);
        assert_eq!(
            decode(&cursor, &[8; 16]),
            CursorDecode::ForeignGeneration,
            "same structure, other generation"
        );
    }

    #[test]
    fn sec_12_7_malformed_cursors_are_invalid_not_reset() {
        for bytes in [&[][..], &[0u8; 23], &[0u8; 25], &[0u8; 128]] {
            assert_eq!(decode(bytes, &GEN), CursorDecode::Malformed, "{bytes:02x?}");
        }
    }
}
