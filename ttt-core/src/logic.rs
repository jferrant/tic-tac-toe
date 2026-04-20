use crate::merkle::{
    compute_root_from_leaves, hash_bytes, hash_leaf, hash_leaf_from_hash, Hash, NULL_HASH,
};

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
/// A helper enum for defining possible error conditions in the STF function
pub enum StfError {
    #[error("Merkle proof verification failed")]
    InvalidMerkleProof,
    #[error("Game is already initialized")]
    GameAlreadyInitialized,
    #[error("Game has not been initialized yet")]
    GameNotInitialized,
    // Note: We use InvalidPlayer now to cover both identity and turn mismatches
    #[error("The provided public key does not match the player record")]
    InvalidPlayer,
    #[error("The target cell ({0}, {1}) is already occupied")]
    CellNotEmpty(usize, usize),
    #[error("Coordinates ({0}, {1}) are out of bounds")]
    OutOfBounds(usize, usize),
    #[error("Player X and Player O cannot have the same public key")]
    IdenticalPlayerKeys,
    #[error("Invalid turn value found in state. Must be 1 (X) or 2 (O)")]
    InvalidTurnValue,
    #[error("The game has already been won by another player")]
    GameAlreadyFinished,
    #[error("The game entered into an invalid state.")]
    InvalidState,
}

pub const WIN_CONDITIONS: [[usize; 3]; 8] = [
    // Rows
    [0, 1, 2],
    [3, 4, 5],
    [6, 7, 8],
    // Columns
    [0, 3, 6],
    [1, 4, 7],
    [2, 5, 8],
    // Diagonals
    [0, 4, 8],
    [2, 4, 6],
];
pub const BOARD_START_IDX: usize = 0;
pub const BOARD_END_IDX: usize = 8;
pub const PLAYER_X_IDX: usize = 9;
pub const PLAYER_O_IDX: usize = 10;
pub const TURN_TRACKER_IDX: usize = 11;
pub const TREE_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// A cell value on our 3x3 board
pub enum Cell {
    Empty = 0,
    X = 1,
    O = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// Whether a player is acting as X's or O's
pub enum PlayerRole {
    X = 1,
    O = 2,
}

impl PlayerRole {
    /// Get the next player's role for calculating turns
    pub fn next(&self) -> Self {
        match self {
            PlayerRole::X => PlayerRole::O,
            PlayerRole::O => PlayerRole::X,
        }
    }

    /// Get the index into the merkle tree for the player's pubkey
    pub fn pubkey_index(&self) -> usize {
        match self {
            PlayerRole::X => PLAYER_X_IDX,
            PlayerRole::O => PLAYER_O_IDX,
        }
    }
}

/// The authenticated state required to execute a single transition.
///
/// The `Witness` contains a full snapshot of the Merkle Tree leaves. This allows
/// the STF to verify the `prior_merkle_root_hash` and perform multiple atomic
/// updates (e.g., updating a board cell AND the turn tracker) without requiring
/// complex Merkle path surgery.
pub struct Witness {
    /// A complete array of all 16 leaves in the Merkle Tree.
    /// Indices are mapped as follows:
    /// - 0..=8:   Tic-Tac-Toe Board (Empty, X, or O)
    /// - 9:       Player X Public Key Hash
    /// - 10:      Player O Public Key Hash
    /// - 11:      Turn Tracker (1 for X, 2 for O)
    /// - 12..=15: Padding (NULL_HASH)
    pub leaves: [Hash; 16],
}

/// A list of valid player moves
#[derive(serde::Deserialize)]
pub enum PlayerMove {
    CreateGame {
        /// The pubkey of the first player (X's)
        pubkey_x: Player,
        /// The pubkey of the second player (O's)
        pubkey_y: Player,
    },
    Play {
        /// The pubkey of the player performing the move
        pubkey: Player,
        /// The cell coordinates being modified
        coords: (usize, usize),
    },
}

/// The public key of a player
pub type Player = [u8; 32];
/// The public key of the winner of a given game.
pub type Winner = Player;

/// Map 2D coordinates (x,y) to a 1D linear index using Row-Major Ordering
/// Since its a 3x3 board: 3y+x
pub fn convert_coordinates_to_index(x: usize, y: usize) -> Result<usize, StfError> {
    if x >= 3 || y >= 3 {
        return Err(StfError::OutOfBounds(x, y));
    }
    Ok(y * 3 + x)
}

/// Check if the latest move resulted in a win.
/// Returns Some(Player) if a line is completed, otherwise None.
fn check_winner(leaves: &[Hash; 16]) -> Option<PlayerRole> {
    for combo in WIN_CONDITIONS {
        let a = leaves[combo[0]];
        let b = leaves[combo[1]];
        let c = leaves[combo[2]];

        // If all three match and are NOT empty
        if a != hash_leaf(Cell::Empty as u8) && a == b && b == c {
            // We need to return the actual Player (pubkey), not just the role.
            // We look at the value in the winning cells to see if it was X or O.
            if a == hash_leaf(PlayerRole::X as u8) {
                return Some(PlayerRole::X);
            } else {
                return Some(PlayerRole::O);
            }
        }
    }
    None
}

/// Initialize the game by building the full Merkle Tree with all 16 leaves
fn init_game(pubkey_x: &Player, pubkey_y: &Player) -> (Hash, [[u8; 32]; 16]) {
    // Start with an array where every leaf is the NULL_HASH constant
    let mut leaves = [NULL_HASH; TREE_SIZE];

    // Indices 0–8: Initialize the board with Empty cells
    for leaf in leaves.iter_mut().take(BOARD_END_IDX + 1) {
        *leaf = hash_leaf(Cell::Empty as u8);
    }

    // Index 9: Player X identity (Hash of the Hash)
    leaves[PLAYER_X_IDX] = hash_leaf_from_hash(hash_bytes(pubkey_x));

    // Index 10: Player O identity (Hash of the Hash)
    leaves[PLAYER_O_IDX] = hash_leaf_from_hash(hash_bytes(pubkey_y));

    // Index 11: Turn Tracker starts with Player X
    leaves[TURN_TRACKER_IDX] = hash_leaf(PlayerRole::X as u8);

    // Note: Indices 12–15 remain NULL_HASH as defined at the start of the function.
    // This distinguishes "game state" leaves from "padding" leaves.

    (compute_root_from_leaves(&leaves), leaves)
}

/// The State Transition Function (STF) that determines if a move is valid or not
/// Ensures that create game is only called once and enforces all tic-tac-toe rules
/// The STF is stateless, using the Merkle Tree to construct its state each time
pub fn stf(
    prior_merkle_root_hash: Hash,
    player_move: &PlayerMove,
    witness: &Witness,
) -> Result<(Hash, [Hash; 16], Option<Winner>), StfError> {
    // Return the 16 leaves too!

    match player_move {
        PlayerMove::CreateGame { pubkey_x, pubkey_y } => {
            // Make sure we don't overwrite an existing game
            if prior_merkle_root_hash != NULL_HASH {
                return Err(StfError::GameAlreadyInitialized);
            }
            // Don't initialize a game with the same players
            if pubkey_x == pubkey_y {
                return Err(StfError::IdenticalPlayerKeys);
            }
            let (new_hash, new_leaves) = init_game(pubkey_x, pubkey_y);
            Ok((new_hash, new_leaves, None))
        }
        PlayerMove::Play { pubkey, coords } => {
            // We don't have a game yet
            if prior_merkle_root_hash == NULL_HASH {
                return Err(StfError::GameNotInitialized);
            }

            // Now we verify that the witness matches the state we are transitioning from
            if compute_root_from_leaves(&witness.leaves) != prior_merkle_root_hash {
                return Err(StfError::InvalidMerkleProof);
            }

            if check_winner(&witness.leaves).is_some() {
                return Err(StfError::GameAlreadyFinished);
            }

            // Verify turn and identify info
            let is_x_turn = witness.leaves[TURN_TRACKER_IDX] == hash_leaf(PlayerRole::X as u8);
            let is_o_turn = witness.leaves[TURN_TRACKER_IDX] == hash_leaf(PlayerRole::O as u8);

            let current_role = if is_x_turn {
                PlayerRole::X
            } else if is_o_turn {
                PlayerRole::O
            } else {
                return Err(StfError::InvalidTurnValue);
            };

            // This part is perfect - handles the double-hash correctly
            let identity_leaf = hash_leaf_from_hash(hash_bytes(pubkey));
            if witness.leaves[current_role.pubkey_index()] != identity_leaf {
                return Err(StfError::InvalidPlayer);
            }

            let board_idx = convert_coordinates_to_index(coords.0, coords.1)?;

            if witness.leaves[board_idx] != hash_leaf(Cell::Empty as u8) {
                return Err(StfError::CellNotEmpty(coords.0, coords.1));
            }

            // State Transition
            let mut new_leaves = witness.leaves;
            new_leaves[board_idx] = hash_leaf(current_role as u8);
            new_leaves[TURN_TRACKER_IDX] = hash_leaf(current_role.next() as u8);

            let winner = if let Some(winner_role) = check_winner(&new_leaves) {
                // This should not ever happen...
                if winner_role != current_role {
                    return Err(StfError::InvalidState);
                }
                Some(*pubkey)
            } else {
                None
            };
            Ok((compute_root_from_leaves(&new_leaves), new_leaves, winner))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn win_detection_and_locking() {
        let pk_x = [1u8; 32];
        let pk_o = [2u8; 32];

        // Setup: X is about to win on the top row [X, X, _]
        let mut leaves = [hash_leaf(Cell::Empty as u8); 16];
        leaves[0] = hash_leaf(Cell::X as u8);
        leaves[1] = hash_leaf(Cell::X as u8);
        leaves[PLAYER_X_IDX] = hash_leaf_from_hash(hash_bytes(&pk_x));
        leaves[PLAYER_O_IDX] = hash_leaf_from_hash(hash_bytes(&pk_o));
        leaves[TURN_TRACKER_IDX] = hash_leaf(PlayerRole::X as u8);

        let root = compute_root_from_leaves(&leaves);
        let witness = Witness { leaves };

        // X plays at (2, 0) to complete the row
        let move_x = PlayerMove::Play {
            pubkey: pk_x,
            coords: (2, 0),
        };
        let (new_root, new_leaves, winner) =
            stf(root, &move_x, &witness).expect("Winning move failed");

        assert_ne!(new_leaves, leaves);
        assert_eq!(winner, Some(pk_x), "X should be declared winner");

        // Try to move again on the won board—should fail with GameAlreadyFinished
        let mut won_leaves = leaves;
        won_leaves[2] = hash_leaf(Cell::X as u8);
        won_leaves[TURN_TRACKER_IDX] = hash_leaf(PlayerRole::O as u8); // STF toggled this!

        assert_eq!(new_leaves, won_leaves);

        let won_witness = Witness { leaves: won_leaves };

        // 2. Attempt a move after the win
        let move_o = PlayerMove::Play {
            pubkey: pk_o,
            coords: (0, 1),
        };

        // This should now pass the Merkle check and hit the GameAlreadyFinished check
        let result = stf(new_root, &move_o, &won_witness);

        assert_eq!(
            result.unwrap_err(),
            StfError::GameAlreadyFinished,
            "Should fail because the board already shows a winner"
        );
    }

    #[test]
    fn check_invalid_player_identity() {
        let pk_x = [1u8; 32];
        let attacker_pk = [9u8; 32];

        let mut leaves = [hash_leaf(Cell::Empty as u8); 16];
        leaves[PLAYER_X_IDX] = hash_leaf_from_hash(hash_bytes(&pk_x));
        leaves[TURN_TRACKER_IDX] = hash_leaf(PlayerRole::X as u8);

        let root = compute_root_from_leaves(&leaves);
        let witness = Witness { leaves };

        // Attacker tries to play as X
        let move_attack = PlayerMove::Play {
            pubkey: attacker_pk,
            coords: (0, 0),
        };
        let result = stf(root, &move_attack, &witness);

        assert_eq!(result.unwrap_err(), StfError::InvalidPlayer);
    }

    #[test]
    fn wrong_turn_order() {
        let pk_x = [1u8; 32];
        let pk_o = [2u8; 32];

        let mut leaves = [hash_leaf(Cell::Empty as u8); 16];
        leaves[PLAYER_X_IDX] = hash_leaf_from_hash(hash_bytes(&pk_x));
        leaves[PLAYER_O_IDX] = hash_leaf_from_hash(hash_bytes(&pk_o));
        leaves[TURN_TRACKER_IDX] = hash_leaf(PlayerRole::O as u8); // It's O's turn

        let root = compute_root_from_leaves(&leaves);
        let witness = Witness { leaves };

        // X tries to move out of turn
        let move_x = PlayerMove::Play {
            pubkey: pk_x,
            coords: (0, 0),
        };
        let result = stf(root, &move_x, &witness);

        // Should fail because pk_x doesn't match the pubkey at the current role's (O) index
        assert_eq!(result.unwrap_err(), StfError::InvalidPlayer);
    }

    #[test]
    fn coordinate_boundary() {
        let pk_x = [1u8; 32];
        let mut leaves = [hash_leaf(Cell::Empty as u8); 16];
        leaves[PLAYER_X_IDX] = hash_leaf_from_hash(hash_bytes(&pk_x));
        leaves[TURN_TRACKER_IDX] = hash_leaf(PlayerRole::X as u8);

        let root = compute_root_from_leaves(&leaves);
        let witness = Witness { leaves };

        // Test extreme out of bounds
        let move_bad = PlayerMove::Play {
            pubkey: pk_x,
            coords: (3, 0),
        };
        let result = stf(root, &move_bad, &witness);

        assert_eq!(result.unwrap_err(), StfError::OutOfBounds(3, 0));
    }
    #[test]
    fn successful_move_and_turn_toggle() {
        let pk_x = [1u8; 32];
        let pk_o = [2u8; 32];

        let (root, leaves) = init_game(&pk_x, &pk_o);
        let witness = Witness { leaves };

        let move_x = PlayerMove::Play {
            pubkey: pk_x,
            coords: (0, 0),
        };

        let (new_root, new_leaves, winner) = stf(root, &move_x, &witness).expect("X move failed");
        assert_ne!(new_leaves, leaves);

        // Manually reconstruct what we expect the leaves to look like
        let mut expected_leaves = leaves;
        expected_leaves[0] = hash_leaf(Cell::X as u8); // X at (0,0)
        expected_leaves[TURN_TRACKER_IDX] = hash_leaf(PlayerRole::O as u8); // Now O's turn

        assert_eq!(new_leaves, expected_leaves);

        let expected_root = compute_root_from_leaves(&expected_leaves);

        assert_eq!(
            new_root, expected_root,
            "STF did not produce the expected Merkle root"
        );
        assert!(winner.is_none());
    }

    #[test]
    fn full_board_draw() {
        let pk_x = [1u8; 32];
        let pk_o = [2u8; 32];

        // Create a board with 8 cells filled in a way that no one has won yet
        // X O X
        // X O O
        // O X _  <- X is about to move here
        let (_, mut leaves) = init_game(&pk_x, &pk_o);
        let cells = [
            Cell::X,
            Cell::O,
            Cell::X,
            Cell::X,
            Cell::O,
            Cell::O,
            Cell::O,
            Cell::X,
            Cell::Empty,
        ];
        for (i, cell) in cells.iter().enumerate() {
            leaves[i] = hash_leaf(*cell as u8);
        }
        leaves[TURN_TRACKER_IDX] = hash_leaf(PlayerRole::X as u8);

        let root = compute_root_from_leaves(&leaves);
        let witness = Witness { leaves };

        let move_x = PlayerMove::Play {
            pubkey: pk_x,
            coords: (2, 2),
        };

        let (_, _, winner) = stf(root, &move_x, &witness).expect("Draw move failed");
        assert!(winner.is_none(), "There should be no winner in a draw");
    }

    #[test]
    fn cell_already_occupied() {
        let pk_x = [1u8; 32];
        let pk_o = [2u8; 32];
        let (_, mut leaves) = init_game(&pk_x, &pk_o);

        // Set (0,0) to X already
        leaves[0] = hash_leaf(Cell::X as u8);
        leaves[TURN_TRACKER_IDX] = hash_leaf(PlayerRole::O as u8);

        let root = compute_root_from_leaves(&leaves);
        let witness = Witness { leaves };

        let move_o = PlayerMove::Play {
            pubkey: pk_o,
            coords: (0, 0),
        };

        let result = stf(root, &move_o, &witness);
        assert_eq!(result.unwrap_err(), StfError::CellNotEmpty(0, 0));
    }

    #[test]
    fn invalid_merkle_witness() {
        let pk_x = [1u8; 32];
        let pk_o = [2u8; 32];
        let (root, leaves) = init_game(&pk_x, &pk_o);

        // Corrupt the witness by changing a padding leaf
        let mut corrupt_leaves = leaves;
        corrupt_leaves[15] = hash_leaf(99);
        let witness = Witness {
            leaves: corrupt_leaves,
        };

        let move_x = PlayerMove::Play {
            pubkey: pk_x,
            coords: (0, 0),
        };

        let result = stf(root, &move_x, &witness);
        assert_eq!(result.unwrap_err(), StfError::InvalidMerkleProof);
    }
}
