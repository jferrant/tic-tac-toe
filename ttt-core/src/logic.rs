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
}

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

/// Initialize the game by building the full Merkle Tree with all 16 leaves
fn init_game(pubkey_x: &Player, pubkey_y: &Player) -> Hash {
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
    compute_root_from_leaves(&leaves)
}

/// The State Transition Function (STF) that determines if a move is valid or not
/// Ensures that create game is only called once and enforces all tic-tac-toe rules
/// The STF is stateless, using the Merkle Tree to construct its state each time
pub fn stf(
    prior_merkle_root_hash: Hash,
    player_move: PlayerMove,
    witness: Witness,
) -> Result<(Hash, Option<Winner>), StfError> {
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
            Ok((init_game(&pubkey_x, &pubkey_y), None))
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
            let identity_leaf = hash_leaf_from_hash(hash_bytes(&pubkey));
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

            // TODO: handle win condition
            Ok((compute_root_from_leaves(&new_leaves), None))
        }
    }
}
