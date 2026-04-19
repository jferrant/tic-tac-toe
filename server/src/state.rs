use std::collections::HashMap;
use std::sync::RwLock;

use tracing::{info, warn};
use ttt_core::logic::{new_game, Player, PlayerRole, TURN_TRACKER_IDX};
use ttt_core::merkle::{hash_bytes, hash_leaf, Hash};

#[derive(Default)]
pub struct AppState {
    pub games: RwLock<HashMap<u128, [Hash; 16]>>,
    next_id: RwLock<u128>,
}

/// Helper function to generate a unique game id given the provided players and provided nonce.
pub fn generate_game_id(pk_x: &Player, pk_y: &Player, nonce: u64) -> u128 {
    let mut inputs = Vec::with_capacity(32 + 32 + 8);
    inputs.extend_from_slice(pk_x);
    inputs.extend_from_slice(pk_y);
    inputs.extend_from_slice(&nonce.to_be_bytes());

    let hash = hash_bytes(&inputs);

    // Take the first 16 bytes of the hash to create a u128
    let mut id_bytes = [0u8; 16];
    id_bytes.copy_from_slice(&hash[..16]);
    u128::from_be_bytes(id_bytes)
}

impl AppState {
    pub fn get_next_game_id(&self) -> u128 {
        let mut id_gen = self.next_id.write().unwrap();
        let id = *id_gen;
        *id_gen += 1;
        id
    }

    /// Create the raw data from the handler
    pub fn create_game(&self, game_id: u128, pk_x: &Player, pk_o: &Player) -> Result<(), String> {
        let mut games = self.games.write().expect("Lock poisoned");
        if games.contains_key(&game_id) {
            return Err("Failed to create game. Game ID {game_id} already exists.".into());
        }
        let game = new_game(pk_x, pk_o);
        games.insert(game_id, game);
        Ok(())
    }

    /// Attempt to apply a move to the given game id
    pub fn apply_move(&self, game_id: u128, x: usize, y: usize, role: PlayerRole) {
        let mut games = self.games.write().expect("Lock poisoned");
        if let Some(leaves) = games.get_mut(&game_id) {
            let idx = y * 3 + x;
            leaves[idx] = hash_leaf(role as u8);
            leaves[TURN_TRACKER_IDX] = hash_leaf(role.next() as u8);
            info!("{role:?} applied a mark to ({x}, {y}");
        } else {
            warn!("Game id ({game_id}) was not found. Not applying move.");
        }
    }

    /// Helper to get a copy of leaves for witness construction
    pub fn get_witness_data(&self, game_id: u128) -> Option<[Hash; 16]> {
        let games = self.games.read().ok()?;
        games.get(&game_id).copied()
    }

    /// Check if the tiven game id already exists
    pub fn game_exists(&self, game_id: u128) -> bool {
        let games = self.games.read().expect("Lock poisoned");
        games.contains_key(&game_id)
    }
}
