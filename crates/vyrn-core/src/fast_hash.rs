//! A multiplicative hasher for the engine's u64-keyed internal caches.
//!
//! `std`'s default SipHash defends maps whose keys an adversary chooses.
//! The page cache and the value cache are keyed by page ids and value-log
//! offsets the engine allocates itself — an attacker cannot pick them — so
//! the DoS defence buys nothing there, and its cost lands on every page
//! read of every descent and every value-cache probe. One odd-constant
//! multiply plus a xor-shift replaces it: the multiply diffuses low bits
//! upward so the map's control bytes (taken from the high bits) vary, and
//! the xor-shift folds them back down for the bucket index.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

/// A `HashMap` keyed by engine-allocated u64 ids, on the fast hasher.
pub(crate) type U64Map<V> = HashMap<u64, V, BuildHasherDefault<U64Hasher>>;

/// A `HashMap` on the fast hasher for keys the engine encodes itself —
/// byte-vector keys hash through the same mix via `write`. Only for maps
/// whose keys an external caller cannot craft freely enough to matter, and
/// whose lookups are hot: a commit's presence overlay probes once per
/// operation of every batch.
pub(crate) type FastMap<K, V> = HashMap<K, V, BuildHasherDefault<U64Hasher>>;

#[derive(Default)]
pub(crate) struct U64Hasher(u64);

impl Hasher for U64Hasher {
    fn write_u64(&mut self, value: u64) {
        // The golden-ratio constant of Fibonacci hashing; any odd constant
        // with mixed bits works, this one is the conventional choice.
        let hashed = value.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        self.0 = hashed ^ (hashed >> 32);
    }

    fn write(&mut self, bytes: &[u8]) {
        // The maps this hasher serves are keyed by u64, which hashes through
        // `write_u64` alone — but a future non-u64 key must hash correctly
        // rather than silently collide, so bytes fold through the same mix.
        for chunk in bytes.chunks(8) {
            let mut word = [0u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            self.write_u64(self.0 ^ u64::from_le_bytes(word));
        }
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sequential ids — which is exactly what page ids are — must spread
    /// across both the bucket-index bits (low) and the control-byte bits
    /// (high), or the map degrades to a scan under its own workload.
    #[test]
    fn sequential_ids_spread_in_low_and_high_bits() {
        let mut low = std::collections::HashSet::new();
        let mut high = std::collections::HashSet::new();
        for id in 0..1024_u64 {
            let mut hasher = U64Hasher::default();
            hasher.write_u64(id);
            let hash = hasher.finish();
            low.insert(hash & 0x3FF);
            high.insert(hash >> 57);
        }
        assert!(low.len() > 512, "low bits collapsed: {}", low.len());
        assert!(high.len() > 100, "high bits collapsed: {}", high.len());
    }
}
