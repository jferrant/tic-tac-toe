use std::collections::HashMap;
use std::sync::RwLock;

use tracing::{info, warn};
use ttt_core::logic::{new_game, Player, PlayerRole, TURN_TRACKER_IDX};
use ttt_core::merkle::{hash_leaf, Hash};

#[derive(Default)]
pub struct AppState {
    pub games: RwLock<HashMap<u128, [Hash; 16]>>,
}

impl AppState {
    /// Create the raw data from the handler
    pub fn create_game(&self, game_id: u128, pk_x: &Player, pk_o: &Player) -> Result<(), String> {
        let mut games = self.games.write().map_err(|_| "Lock poisoned")?;
        if games.contains_key(&game_id) {
            return Err("Failed to create game. Game ID {game_id} already exists.".into());
        }
        let game = new_game(pk_x, pk_o);
        games.insert(game_id, game);
        Ok(())
    }

    /// Attempt to apply a move to the given game id
    pub fn apply_move(&self, game_id: u128, x: usize, y: usize, role: PlayerRole) {
        let mut games = self.games.write().unwrap();
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
}
