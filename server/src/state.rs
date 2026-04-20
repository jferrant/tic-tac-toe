use std::collections::HashMap;
use std::sync::RwLock;

use ttt_core::logic::Player;
use ttt_core::merkle::{hash_bytes, Hash};

#[derive(Default)]
pub struct AppState {
    pub games: RwLock<HashMap<u128, [Hash; 16]>>,
    next_id: RwLock<u128>,
}

/// Helper function to generate a unique game id.
/// The creator (pk_x) is always assigned the role of X.
pub fn generate_game_id(pk_x: &Player, pk_y: &Player, nonce: u128) -> u128 {
    // 32 (pk_x) + 32 (pk_y) + 16 (u128 nonce) = 80 bytes
    let mut inputs = Vec::with_capacity(80);
    inputs.extend_from_slice(pk_x);
    inputs.extend_from_slice(pk_y);
    inputs.extend_from_slice(&nonce.to_be_bytes());

    let hash = hash_bytes(&inputs);

    // Take the first 16 bytes of the hash to create a u128 game identifier
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

#[cfg(test)]
mod tests {
    use super::*;
    use ttt_core::merkle::NULL_HASH;

    // Helper to create a dummy player pubkey
    fn dummy_player(val: u8) -> Player {
        [val; 32]
    }

    // Helper to create a dummy board state
    fn dummy_leaves() -> [Hash; 16] {
        [NULL_HASH; 16]
    }

    #[test]
    fn generate_game_id_determinism() {
        let pk_x = dummy_player(1);
        let pk_y = dummy_player(2);
        let nonce = 42u128;

        let id1 = generate_game_id(&pk_x, &pk_y, nonce);
        let id2 = generate_game_id(&pk_x, &pk_y, nonce);

        // Determinism: Same inputs must yield same ID
        assert_eq!(id1, id2);

        // Uniqueness: Changing the nonce must change the ID
        let id3 = generate_game_id(&pk_x, &pk_y, nonce + 1);
        assert_ne!(id1, id3);

        // Order sensitivity: Swapping players should change the ID
        let id_swapped = generate_game_id(&pk_y, &pk_x, nonce);
        assert_ne!(id1, id_swapped);
    }

    #[test]
    fn app_state_game_lifecycle() {
        let state = AppState::default();
        let game_id = 12345u128;
        let leaves = dummy_leaves();

        // Initially game should not exist
        assert!(!state.game_exists(game_id));
        assert!(state.get_witness_data(game_id).is_none());

        // Create the game
        state.create_game(game_id, leaves).expect("Creation failed");
        assert!(state.game_exists(game_id));

        // Retrieve witness data
        let retrieved = state.get_witness_data(game_id).expect("Data missing");
        assert_eq!(retrieved, leaves);

        // Update the game state
        let mut new_leaves = leaves;
        new_leaves[0] = [0xFF; 32]; // Simulate a move
        state
            .update_game_state(game_id, new_leaves)
            .expect("Update failed");

        let updated = state.get_witness_data(game_id).unwrap();
        assert_eq!(updated[0], [0xFF; 32]);
    }

    #[test]
    fn create_game_conflict() {
        let state = AppState::default();
        let game_id = 999u128;
        let leaves = dummy_leaves();

        state.create_game(game_id, leaves).unwrap();

        // Attempting to create the same ID again should fail
        let result = state.create_game(game_id, leaves);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));
    }

    #[test]
    fn update_non_existent_game() {
        let state = AppState::default();
        let result = state.update_game_state(777, dummy_leaves());
        assert!(result.is_err());
    }

    #[test]
    fn sequential_id_generation() {
        let state = AppState::default();

        let id0 = state.get_next_game_id();
        let id1 = state.get_next_game_id();
        let id2 = state.get_next_game_id();

        assert_eq!(id0, 0);
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    #[test]
    fn concurrent_id_access() {
        use std::sync::Arc;
        use std::thread;

        let state = Arc::new(AppState::default());
        let mut handles = vec![];

        // Spawn 10 threads each requesting an ID
        for _ in 0..10 {
            let s = Arc::clone(&state);
            handles.push(thread::spawn(move || s.get_next_game_id()));
        }

        let mut results: Vec<u128> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        results.sort();

        // Ensure we got 10 unique IDs from 0 to 9
        for (i, result) in results.iter().enumerate() {
            assert_eq!(*result, i as u128);
        }
    }
}
