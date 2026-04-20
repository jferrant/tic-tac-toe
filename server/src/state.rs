use std::collections::HashMap;
use std::sync::RwLock;

use ttt_core::logic::{Cell, Player, PlayerRole};
use ttt_core::merkle::{hash_bytes, Hash};

/// Per-game state stored by the server.
/// Keeps a compact representation so witness construction is trivial.
#[derive(Clone)]
pub struct StoredGame {
    pub root: Hash,
    pub board: [Cell; 9],
    pub turn: PlayerRole,
    pub pk_x: Player,
    pub pk_o: Player,
}

#[derive(Default)]
pub struct AppState {
    pub games: RwLock<HashMap<u128, StoredGame>>,
}

pub fn generate_game_id(pk_x: &Player, pk_y: &Player, nonce: u128) -> u128 {
    let mut inputs = Vec::with_capacity(80);
    inputs.extend_from_slice(pk_x);
    inputs.extend_from_slice(pk_y);
    inputs.extend_from_slice(&nonce.to_be_bytes());
    let hash = hash_bytes(&inputs);
    let mut id_bytes = [0u8; 16];
    id_bytes.copy_from_slice(&hash[..16]);
    u128::from_be_bytes(id_bytes)
}

impl AppState {
    pub fn game_exists(&self, game_id: u128) -> bool {
        self.games
            .read()
            .expect("Lock poisoned")
            .contains_key(&game_id)
    }

    pub fn create_game(&self, game_id: u128, game: StoredGame) -> Result<(), String> {
        let mut games = self
            .games
            .write()
            .map_err(|_| "Lock poisoned".to_string())?;
        if games.contains_key(&game_id) {
            return Err(format!("Conflict: Game ID {game_id} already exists."));
        }
        games.insert(game_id, game);
        Ok(())
    }

    pub fn get_game(&self, game_id: u128) -> Option<StoredGame> {
        let games = self.games.read().ok()?;
        games.get(&game_id).cloned()
    }

    pub fn update_game(
        &self,
        game_id: u128,
        new_root: Hash,
        new_board: [Cell; 9],
        new_turn: PlayerRole,
    ) -> Result<(), String> {
        let mut games = self.games.write().map_err(|_| "Lock poisoned")?;
        let game = games.get_mut(&game_id).ok_or("Game not found")?;
        game.root = new_root;
        game.board = new_board;
        game.turn = new_turn;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ttt_core::logic::{Cell, PlayerRole};
    use ttt_core::merkle::NULL_HASH;

    // Helper to create a dummy player pubkey
    fn dummy_player(val: u8) -> Player {
        [val; 32]
    }

    // Helper to create a basic StoredGame
    fn dummy_game() -> StoredGame {
        StoredGame {
            root: [0xAA; 32], // Dummy root
            board: [Cell::Empty; 9],
            turn: PlayerRole::X,
            pk_x: dummy_player(1),
            pk_o: dummy_player(2),
        }
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
        let game = dummy_game();

        // Initially game should not exist
        assert!(!state.game_exists(game_id));
        assert!(state.get_game(game_id).is_none());

        // Create the game
        state
            .create_game(game_id, game.clone())
            .expect("Creation failed");
        assert!(state.game_exists(game_id));

        // Retrieve and verify data
        let retrieved = state.get_game(game_id).expect("Data missing");
        assert_eq!(retrieved.root, game.root);
        assert_eq!(retrieved.pk_x, game.pk_x);

        // Update the game state (Simulate a move)
        let new_root = [0xBB; 32];
        let mut new_board = game.board;
        new_board[0] = Cell::X;
        let new_turn = PlayerRole::O;

        state
            .update_game(game_id, new_root, new_board, new_turn)
            .expect("Update failed");

        let updated = state.get_game(game_id).unwrap();
        assert_eq!(updated.root, new_root);
        assert_eq!(updated.board[0], Cell::X);
        assert_eq!(updated.turn, PlayerRole::O);
    }

    #[test]
    fn create_game_conflict() {
        let state = AppState::default();
        let game_id = 999u128;
        let game = dummy_game();

        state.create_game(game_id, game.clone()).unwrap();

        // Attempting to create the same ID again should fail
        let result = state.create_game(game_id, game);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));
    }

    #[test]
    fn update_non_existent_game() {
        let state = AppState::default();
        let result = state.update_game(777, NULL_HASH, [Cell::Empty; 9], PlayerRole::X);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Game not found");
    }
}
