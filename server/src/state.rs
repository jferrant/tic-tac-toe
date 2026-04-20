use std::collections::HashMap;
use std::sync::RwLock;

use ttt_core::logic::Player;
use ttt_core::merkle::{hash_bytes, Hash};

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
    pub fn create_game(&self, game_id: u128, leaves: [Hash; 16]) -> Result<(), String> {
        // Acquire the write lock so no one else adds a game with the same id as me
        let mut games = self
            .games
            .write()
            .map_err(|_| "Lock poisoned".to_string())?;

        if games.contains_key(&game_id) {
            // Use format! so the actual ID shows up in your logs/error response
            return Err(format!("Conflict: Game ID {game_id} already exists."));
        }

        games.insert(game_id, leaves);
        Ok(())
    }

    /// Update the game state using the provided new leaves.
    pub fn update_game_state(&self, game_id: u128, new_leaves: [Hash; 16]) -> Result<(), String> {
        let mut games = self.games.write().map_err(|_| "Lock poisoned")?;
        if let Some(game) = games.get_mut(&game_id) {
            *game = new_leaves;
            Ok(())
        } else {
            Err("Game ID {game_id} not found".to_string())
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
