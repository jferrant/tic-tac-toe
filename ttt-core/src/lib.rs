//! # Tic-Tac-Toe ZK-STF
//!
//! This crate will implement the pure logic for a verifiable Tic-Tac-Toe game.
//! It will use a manual Merkle Tree implementation to satisfy the constraint of
//! non-compact state representation.

pub mod logic;
/// A custom Merkle Tree implementation tailored for a 3x3 Tic-Tac-Toe board.
///
/// Since the board contains 9 cells, we use a fixed-height tree of 4 levels
/// (2^4 = 16 leaves) to provide ample capacity. The implementation uses
/// bitwise navigation to determine whether a given index follows a left
/// or right path during root reconstruction.
pub mod merkle;
