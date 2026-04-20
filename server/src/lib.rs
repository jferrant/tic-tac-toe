//! Stateful coordinator for the ZK-verifiable Tic-Tac-Toe game.
//!
//! This crate bridges signed player actions and the pure [`ttt_core`] STF.
//! It owns no game logic — all validation runs through `stf` or `batch_stf`
//! before any state is written.

pub mod handlers;
pub mod models;
pub mod state;
