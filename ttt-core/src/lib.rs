//! Pure game logic for ZK-verifiable Tic-Tac-Toe.
//!
//! This crate has no I/O or server dependencies and can be compiled directly
//! into a zkVM guest. It exposes two entry points:
//!
//! - [`logic::stf`] — verify and apply a single authenticated move
//! - [`logic::batch_stf`] — verify and apply a sequence of moves in one shot
//!
//! All game state is committed to a 16-leaf SHA-256 Merkle tree (see [`merkle`]).
//! The Merkle root is the sole public input to the STF; the witness supplies the
//! compact pre-image data needed to reconstruct and check it.

pub mod logic;
pub mod merkle;
