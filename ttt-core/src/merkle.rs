use sha2::{Digest, Sha256};

pub const NULL_HASH: Hash = [0u8; 32];
/// The hash representation of leaf in our Merkle Tree.
pub type Hash = [u8; 32];

/// Internal helper to ensure ALL leaves are prefixed with 0
fn hash_leaf_raw(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0]); // The "Leaf" prefix
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash a single byte leaf (Board Squares, Turn Tracker)
pub fn hash_leaf(leaf: u8) -> Hash {
    hash_leaf_raw(&[leaf])
}

/// Hash a 32-byte commitment (Player Pubkeys)
pub fn hash_leaf_from_hash(h: Hash) -> Hash {
    hash_leaf_raw(&h)
}

/// Standard SHA-256 for general data (not yet a leaf)
pub fn hash_bytes(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
/// Hash two nodes together. Used to create the parent node hash of its children.
pub fn hash_nodes(left: Hash, right: Hash) -> Hash {
    let mut hasher = Sha256::default();
    // We could theoretically (though super unlikely)
    // hash a leaf and a node as the same value. Add a
    // prefix so we know this can never happen.
    hasher.update([1]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Compute the root of a merkle tree without heap allocations (no to_vec).
/// This implementation uses a stack-based buffer to process the tree levels.
pub fn compute_root_from_leaves(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return NULL_HASH;
    }

    // A height-4 tree (16 leaves) only needs a stack of size 5 to store
    // intermediate hashes. We'll use 32 as a safe upper bound for any tree.
    let mut stack: [Option<Hash>; 32] = [None; 32];

    for &leaf in leaves {
        let mut current_hash = leaf;

        // "Climb" the tree: if there is a hash at the current level,
        // combine them and move to the level above.
        for level in stack.iter_mut() {
            match level {
                Some(sibling_hash) => {
                    current_hash = hash_nodes(*sibling_hash, current_hash);
                    *level = None;
                }
                None => {
                    *level = Some(current_hash);
                    break;
                }
            }
        }
    }

    // Final reduction: hash all remaining items in the stack from bottom to top.
    let mut root: Option<Hash> = None;
    for node in stack.iter().flatten() {
        match root {
            None => root = Some(*node),
            Some(prev_node) => root = Some(hash_nodes(*node, prev_node)),
        }
    }

    root.unwrap_or(NULL_HASH)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verify_known_hash_values() {
        let h_empty = hash_leaf(0);
        let h_x = hash_leaf(1);
        let h_o = hash_leaf(2);

        // Correct SHA-256 for [0x00, 0]
        let expected_empty = [
            0x96, 0xa2, 0x96, 0xd2, 0x24, 0xf2, 0x85, 0xc6, 0x7b, 0xee, 0x93, 0xc3, 0x0f, 0x8a,
            0x30, 0x91, 0x57, 0xf0, 0xda, 0xa3, 0x5d, 0xc5, 0xb8, 0x7e, 0x41, 0x0b, 0x78, 0x63,
            0x0a, 0x09, 0xcf, 0xc7,
        ];

        // Correct SHA-256 for [0x00, 1]
        let expected_x = [
            0xb4, 0x13, 0xf4, 0x7d, 0x13, 0xee, 0x2f, 0xe6, 0xc8, 0x45, 0xb2, 0xee, 0x14, 0x1a,
            0xf8, 0x1d, 0xe8, 0x58, 0xdf, 0x4e, 0xc5, 0x49, 0xa5, 0x8b, 0x79, 0x70, 0xbb, 0x96,
            0x64, 0x5b, 0xc8, 0xd2,
        ];

        // Correct SHA-256 for [0x00, 2]
        let expected_o = [
            0xfc, 0xf0, 0xa6, 0xc7, 0x00, 0xdd, 0x13, 0xe2, 0x74, 0xb6, 0xfb, 0xa8, 0xde, 0xea,
            0x8d, 0xd9, 0xb2, 0x6e, 0x4e, 0xed, 0xde, 0x34, 0x95, 0x71, 0x7c, 0xac, 0x84, 0x08,
            0xc9, 0xc5, 0x17, 0x7f,
        ];

        assert_eq!(h_empty, expected_empty, "Empty leaf hash mismatch");
        assert_eq!(h_x, expected_x, "X leaf hash mismatch");
        assert_eq!(h_o, expected_o, "O leaf hash mismatch");
    }

    #[test]
    fn verify_domain_separation() {
        let h_leaf = hash_leaf(0);
        // Even if we hash two identical things, a node hash
        // should be distinct from a leaf hash.
        let h_node = hash_nodes(h_leaf, h_leaf);

        assert_ne!(h_leaf, h_node, "Leaf and Node hashes should not collide");
    }

    #[test]
    fn verify_hash_nodes_order() {
        let h0 = hash_leaf(0);
        let h1 = hash_leaf(1);

        let left_right = hash_nodes(h0, h1);
        let right_left = hash_nodes(h1, h0);

        assert_ne!(
            left_right, right_left,
            "Merkle trees is not order-sensitive."
        );
    }

    #[test]
    fn verify_hash_bytes_deterministic() {
        let input = b"in a galaxy far far away";
        let hash1 = hash_bytes(input);
        let hash2 = hash_bytes(input);

        // Same input must result in the same hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn verify_hash_bytes_known_value() {
        let input = b"abc";
        let expected: Hash = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];

        assert_eq!(hash_bytes(input), expected);
    }

    #[test]
    fn verify_hash_bytes_different_inputs() {
        let hash_a = hash_bytes(b"player_x");
        let hash_b = hash_bytes(b"player_o");

        // Different inputs must result in different hashes
        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn compute_root_small_tree() {
        // Create 4 distinct leaves
        let l0 = hash_leaf(0);
        let l1 = hash_leaf(1);
        let l2 = hash_leaf(2);
        let l3 = hash_leaf(3);
        let leaves = vec![l0, l1, l2, l3];

        // Manually calculate the expected root:
        // Level 1: [Hash(l0, l1), Hash(l2, l3)]
        // Level 2: Hash(Hash(l0, l1), Hash(l2, l3))
        let row1_0 = hash_nodes(l0, l1);
        let row1_1 = hash_nodes(l2, l3);
        let expected_root = hash_nodes(row1_0, row1_1);

        let result = compute_root_from_leaves(&leaves);
        assert_eq!(result, expected_root, "Small tree root mismatch");
    }

    #[test]
    fn compute_root_16_leaves() {
        // This simulates your actual Tic-Tac-Toe game state setup
        let mut leaves = [hash_leaf(0); 16];

        // Change a few leaves to ensure it's not just hashing zeros
        leaves[0] = hash_leaf(1); // Player X move
        leaves[9] = hash_leaf_from_hash(hash_bytes(b"player_x_pubkey"));
        leaves[11] = hash_leaf(2); // Turn tracker set to O

        let root = compute_root_from_leaves(&leaves);

        // A basic property of Merkle roots:
        // Changing one leaf MUST change the root.
        leaves[0] = hash_leaf(2);
        let new_root = compute_root_from_leaves(&leaves);

        assert_ne!(root, new_root, "Root failed to change after leaf update");
        assert_ne!(root, [0u8; 32], "Root should not be empty");
    }

    #[test]
    fn compute_root_consistency() {
        // Ensure that hashing 16 leaves results in the same value as
        // hashing the two parent 8-leaf chunks.
        let leaves = [hash_leaf(1); 16];

        let full_root = compute_root_from_leaves(&leaves);

        // Manually compute the two halves (8 leaves each)
        let left_child = compute_root_from_leaves(&leaves[0..8]);
        let right_child = compute_root_from_leaves(&leaves[8..16]);

        // The root of the 16 should be the hash of the two 8-leaf roots
        let combined_root = hash_nodes(left_child, right_child);

        assert_eq!(full_root, combined_root, "Hierarchical consistency failed");
    }
}
