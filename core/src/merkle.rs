use sha2::{Digest, Sha256};

/// The hash representation of leaf in our Merkle Tree.
pub type Hash = [u8; 32];

/// Hash a single leaf of the Merkle Tree.
pub fn hash_leaf(leaf: u8) -> Hash {
    let mut hasher = Sha256::default();
    // We could theoretically (though super unlikely)
    // hash a leaf and a node as the same value. Add a
    // prefix so we know this can never happen.
    hasher.update([0]);
    hasher.update([leaf]);
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

/// Reconstruct a root from its siblings.
///
/// Traverses the tree up, checking if the node we are currently at is the left or right child of the parent.
/// It will continually hash itself with its sibling until it reaches the root hash.
///
/// ### How the bitwise "Directions" work:
/// We look at the binary form of the index (e.g., index 2 is `0010`). Each bit
/// tells us our position at that specific level (starting from the bottom):
///
/// 1. `index >> i`: We move to the bit for our current level.
/// 2. `& 1`: We check if that bit is a 0 or a 1.
///
/// - **If the bit is 0**: We are the **Left** piece of the pair. We put our
///   `current_hash` first and the `sibling` second.
/// - **If the bit is 1**: We are the **Right** piece of the pair. We put the
///   `sibling` first and our `current_hash` second.
///
/// Example: For Index 2 (`0010` in binary):
/// - Level 0 (Right-most bit '0'): We're on the left. Hash as `(Me, Sibling)`.
/// - Level 1 (Bit '1'): We're on the right. Hash as `(Sibling, Me)`.
/// - Level 2 (Bit '0'): Back on the left. Hash as `(Me, Sibling)`.
/// - Level 3 (Bit '0'): Still on the left. Hash as `(Me, Sibling)`.
pub fn calculate_root_from_path(index: usize, mut current_hash: Hash, path: &[Hash]) -> Hash {
    for (i, sibling) in path.iter().enumerate() {
        // Look at the ith bit of the index.
        if (index >> i) & 1 == 0 {
            // we are the left child and sibling is the right;
            current_hash = hash_nodes(current_hash, *sibling);
        } else {
            // we are the right child and sibling is the left;
            current_hash = hash_nodes(*sibling, current_hash);
        }
    }
    current_hash
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
    fn verify_root_from_path() {
        // Path for Index 2 (Binary: 0010)
        // Level 0 bit is 0 -> We are LEFT
        // Level 1 bit is 1 -> We are RIGHT
        // Level 2 bit is 0 -> We are LEFT
        // Level 3 bit is 0 -> We are LEFT

        let leaf_val = 1u8; // Player X
        let current_hash = hash_leaf(leaf_val);

        // Mock siblings for a height-4 tree
        let s1 = [1u8; 32];
        let s2 = [2u8; 32];
        let s3 = [3u8; 32];
        let s4 = [4u8; 32];
        let path = vec![s1, s2, s3, s4];

        // Manually calculate what the root SHOULD be based on Index 2 directions:
        // 1. Bit 0 is 0: Parent = Hash(current, s1)
        let p1 = hash_nodes(current_hash, s1);
        // 2. Bit 1 is 1: Parent = Hash(s2, p1)  <-- Sibling is LEFT
        let p2 = hash_nodes(s2, p1);
        // 3. Bit 2 is 0: Parent = Hash(p2, s3)
        let p3 = hash_nodes(p2, s3);
        // 4. Bit 3 is 0: Parent = Hash(p3, s4)
        let expected_root = hash_nodes(p3, s4);

        let result_root = calculate_root_from_path(2, current_hash, &path);

        assert_eq!(
            result_root, expected_root,
            "Root calculation failed for index 2! Check bit-shifting order."
        );
    }

    #[test]
    fn verify_root_index_zero() {
        // Index 0 is binary 0000. All steps should be (Current, Sibling)
        let current_hash = hash_leaf(0);
        let s = [0xAA; 32];
        let path = vec![s, s, s, s];

        let p1 = hash_nodes(current_hash, s);
        let p2 = hash_nodes(p1, s);
        let p3 = hash_nodes(p2, s);
        let p4 = hash_nodes(p3, s);

        let result = calculate_root_from_path(0, current_hash, &path);
        assert_eq!(result, p4);
    }
}
