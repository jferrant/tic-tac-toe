use ed25519_dalek::{Signature, Verifier, VerifyingKey};

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
    #[error("The player provided an invalid signature")]
    InvalidSignature,
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
/// complex Merkle path surgery. The full path is required to verify a board win state anyway.
pub struct Witness {
    /// A complete array of all 16 leaves in the Merkle Tree.
    /// Indices are mapped as follows:
    /// - 0..=8:   Tic-Tac-Toe Board (Empty, X, or O)
    /// - 9:       Player X Public Key Hash
    /// - 10:      Player O Public Key Hash
    /// - 11:      Turn Tracker (1 for X, 2 for O)
    /// - 12..=15: Padding (NULL_HASH)
    pub leaves: [Hash; 16],
    /// The cryptographic proof that the player authorized this specific move
    pub signature: [u8; 64],
}

/// A list of valid player moves
#[derive(serde::Deserialize)]
pub enum PlayerMove {
    CreateGame {
        /// The pubkey of the first player (X's)
        pubkey_x: Player,
        /// The pubkey of the second player (O's)
        pubkey_y: Player,
        /// The nonce of the game to accomodate multiple games by the same players
        nonce: u128,
    },
    Play {
        /// The pubkey of the player performing the move
        pubkey: Player,
        /// The cell coordinates being modified
        coords: (usize, usize),
    },
}
impl PlayerMove {
    pub fn get_pubkey(&self) -> &Player {
        match self {
            PlayerMove::CreateGame {
                pubkey_x: pubkey, ..
            }
            | PlayerMove::Play { pubkey, .. } => pubkey,
        }
    }
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
pub fn init_game(pubkey_x: &Player, pubkey_y: &Player) -> (Hash, [[u8; 32]; 16]) {
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

/// Pure function to verify that the provided public key belongs to the
/// player authorized to move in the current state.
fn verify_identity_matches_state(
    pubkey: &Player,
    leaves: &[Hash; 16],
) -> Result<PlayerRole, StfError> {
    // Identify current role from turn tracker
    let turn_hash = leaves[TURN_TRACKER_IDX];
    let current_role = if turn_hash == hash_leaf(PlayerRole::X as u8) {
        PlayerRole::X
    } else if turn_hash == hash_leaf(PlayerRole::O as u8) {
        PlayerRole::O
    } else {
        return Err(StfError::InvalidTurnValue);
    };

    // Reconstruct the leaf for the provided pubkey
    // This MUST match the logic in init_game: hash_leaf_from_hash(hash_bytes(key))
    let identity_leaf = hash_leaf_from_hash(hash_bytes(pubkey));

    // Check current role's registered key in the state
    if leaves[current_role.pubkey_index()] != identity_leaf {
        return Err(StfError::InvalidPlayer);
    }

    Ok(current_role)
}

/// Deterministically serializes a move and the prior state into a message for signing.
/// This ensures the signature is bound to a specific game state (preventing replay attacks).
pub fn format_auth_message(player_move: &PlayerMove, prior_root: Hash) -> Vec<u8> {
    let mut message = Vec::new();
    match player_move {
        PlayerMove::CreateGame {
            pubkey_x,
            pubkey_y,
            nonce,
        } => {
            message.extend_from_slice(b"CREATE_GAME:");
            message.extend_from_slice(pubkey_x);
            message.extend_from_slice(pubkey_y);
            message.extend_from_slice(&nonce.to_be_bytes());
        }
        PlayerMove::Play { pubkey, coords } => {
            message.extend_from_slice(b"PLAY:");
            message.extend_from_slice(pubkey);
            // STABILIZE: Use u32 to ensure 4-byte alignment regardless of architecture
            message.extend_from_slice(&(coords.0 as u32).to_be_bytes());
            message.extend_from_slice(&(coords.1 as u32).to_be_bytes());
            message.extend_from_slice(&prior_root);
        }
    }
    message
}

/// Verify the signature is correct
pub fn verify_signature(
    pubkey: &Player,
    message: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<(), StfError> {
    let public_key = VerifyingKey::from_bytes(pubkey).map_err(|_| StfError::InvalidPlayer)?;

    let signature = Signature::from_bytes(signature_bytes);

    public_key
        .verify(message, &signature)
        .map_err(|_| StfError::InvalidSignature)
}

/// The State Transition Function (STF) that determines if a move is valid or not
/// Ensures that create game is only called once and enforces all tic-tac-toe rules
/// The STF is stateless, using the Merkle Tree to construct its state each time
pub fn stf(
    prior_merkle_root_hash: Hash,
    player_move: &PlayerMove,
    witness: &Witness,
) -> Result<(Hash, [Hash; 16], Option<Winner>), StfError> {
    // Authentication (Always verify signature matches the move intent)
    let pubkey = player_move.get_pubkey();
    let message = format_auth_message(player_move, prior_merkle_root_hash);
    verify_signature(pubkey, &message, &witness.signature)?;

    match player_move {
        PlayerMove::CreateGame {
            pubkey_x, pubkey_y, ..
        } => {
            if prior_merkle_root_hash != NULL_HASH {
                return Err(StfError::GameAlreadyInitialized);
            }
            if pubkey_x == pubkey_y {
                return Err(StfError::IdenticalPlayerKeys);
            }

            // Note: We don't call verify_identity_matches_state here because the state is empty.
            let (new_hash, new_leaves) = init_game(pubkey_x, pubkey_y);
            Ok((new_hash, new_leaves, None))
        }
        PlayerMove::Play { pubkey, coords } => {
            // We don't have a game yet..
            // Integrity: Check the witness matches our prior merkle root hash
            let calculated_root = compute_root_from_leaves(&witness.leaves);
            if calculated_root != prior_merkle_root_hash {
                return Err(StfError::InvalidMerkleProof);
            }
            if prior_merkle_root_hash == NULL_HASH {
                return Err(StfError::GameNotInitialized);
            }

            // Turn/Identity Verification (Specific to Play move)
            let current_role = verify_identity_matches_state(pubkey, &witness.leaves)?;

            if check_winner(&witness.leaves).is_some() {
                return Err(StfError::GameAlreadyFinished);
            }

            let board_idx = convert_coordinates_to_index(coords.0, coords.1)?;
            if witness.leaves[board_idx] != hash_leaf(Cell::Empty as u8) {
                return Err(StfError::CellNotEmpty(coords.0, coords.1));
            }
            // State transition
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
    use ed25519_dalek::{Signer, SigningKey};

    fn signing_key(seed: &[u8; 32]) -> SigningKey {
        SigningKey::from_bytes(seed)
    }

    fn verifying_key(seed: &[u8; 32]) -> Player {
        SigningKey::from_bytes(seed).verifying_key().to_bytes()
    }

    fn sign_move(sk: &SigningKey, player_move: &PlayerMove, prior_root: Hash) -> [u8; 64] {
        let message = format_auth_message(player_move, prior_root);
        sk.sign(&message).to_bytes()
    }

    #[test]
    fn win_detection_and_locking() {
        let sk_x = signing_key(&[1u8; 32]);
        let sk_o = signing_key(&[2u8; 32]);
        let pk_x = verifying_key(&[1u8; 32]);
        let pk_o = verifying_key(&[2u8; 32]);

        // Setup: X is about to win on the top row [X, X, _]
        let mut leaves = [hash_leaf(Cell::Empty as u8); 16];
        leaves[0] = hash_leaf(Cell::X as u8);
        leaves[1] = hash_leaf(Cell::X as u8);
        leaves[PLAYER_X_IDX] = hash_leaf_from_hash(hash_bytes(&pk_x));
        leaves[PLAYER_O_IDX] = hash_leaf_from_hash(hash_bytes(&pk_o));
        leaves[TURN_TRACKER_IDX] = hash_leaf(PlayerRole::X as u8);

        let prior_root = compute_root_from_leaves(&leaves);
        let move_x = PlayerMove::Play {
            pubkey: pk_x,
            coords: (2, 0),
        };

        let witness = Witness {
            leaves,
            signature: sign_move(&sk_x, &move_x, prior_root),
        };

        let (new_root, new_leaves, winner) =
            stf(prior_root, &move_x, &witness).expect("Winning move failed");

        assert_eq!(winner, Some(pk_x), "X should be declared winner");

        // Attempt O move after X has already won
        let move_o = PlayerMove::Play {
            pubkey: pk_o,
            coords: (0, 1),
        };

        let won_witness = Witness {
            leaves: new_leaves,
            signature: sign_move(&sk_o, &move_o, new_root),
        };

        let result = stf(new_root, &move_o, &won_witness);
        assert_eq!(result.unwrap_err(), StfError::GameAlreadyFinished);
    }

    #[test]
    fn check_invalid_player_identity() {
        let pk_x = verifying_key(&[1u8; 32]);
        let sk_attacker = signing_key(&[9u8; 32]);
        let attacker_pk = verifying_key(&[9u8; 32]);

        let mut leaves = [hash_leaf(Cell::Empty as u8); 16];
        leaves[PLAYER_X_IDX] = hash_leaf_from_hash(hash_bytes(&pk_x));
        leaves[TURN_TRACKER_IDX] = hash_leaf(PlayerRole::X as u8);

        let prior_root = compute_root_from_leaves(&leaves);

        let move_attack = PlayerMove::Play {
            pubkey: attacker_pk,
            coords: (0, 0),
        };

        let witness = Witness {
            leaves,
            signature: sign_move(&sk_attacker, &move_attack, prior_root),
        };

        let result = stf(prior_root, &move_attack, &witness);
        assert_eq!(result.unwrap_err(), StfError::InvalidPlayer);
    }

    #[test]
    fn wrong_turn_order() {
        let sk_x = signing_key(&[1u8; 32]);
        let pk_x = verifying_key(&[1u8; 32]);
        let pk_o = verifying_key(&[2u8; 32]);

        let mut leaves = [hash_leaf(Cell::Empty as u8); 16];
        leaves[PLAYER_X_IDX] = hash_leaf_from_hash(hash_bytes(&pk_x));
        leaves[PLAYER_O_IDX] = hash_leaf_from_hash(hash_bytes(&pk_o));
        leaves[TURN_TRACKER_IDX] = hash_leaf(PlayerRole::O as u8); // It's O's turn

        let prior_root = compute_root_from_leaves(&leaves);

        let move_x = PlayerMove::Play {
            pubkey: pk_x,
            coords: (0, 0),
        };

        let witness = Witness {
            leaves,
            signature: sign_move(&sk_x, &move_x, prior_root),
        };

        let result = stf(prior_root, &move_x, &witness);
        assert_eq!(result.unwrap_err(), StfError::InvalidPlayer);
    }

    #[test]
    fn coordinate_boundary() {
        let sk_x = signing_key(&[1u8; 32]);
        let pk_x = verifying_key(&[1u8; 32]);
        let pk_o = verifying_key(&[2u8; 32]);
        let (root, leaves) = init_game(&pk_x, &pk_o);

        let move_bad = PlayerMove::Play {
            pubkey: pk_x,
            coords: (3, 0),
        };

        let witness = Witness {
            leaves,
            signature: sign_move(&sk_x, &move_bad, root),
        };

        let result = stf(root, &move_bad, &witness);
        assert_eq!(result.unwrap_err(), StfError::OutOfBounds(3, 0));
    }

    #[test]
    fn successful_move_and_turn_toggle() {
        let sk_x = signing_key(&[1u8; 32]);
        let pk_x = verifying_key(&[1u8; 32]);
        let pk_o = verifying_key(&[2u8; 32]);

        let (prior_root, leaves) = init_game(&pk_x, &pk_o);
        let move_x = PlayerMove::Play {
            pubkey: pk_x,
            coords: (0, 0),
        };

        let witness = Witness {
            leaves,
            signature: sign_move(&sk_x, &move_x, prior_root),
        };

        let (new_root, new_leaves, winner) =
            stf(prior_root, &move_x, &witness).expect("X move failed");

        let mut expected_leaves = leaves;
        expected_leaves[0] = hash_leaf(Cell::X as u8);
        expected_leaves[TURN_TRACKER_IDX] = hash_leaf(PlayerRole::O as u8);

        assert_eq!(new_leaves, expected_leaves);
        assert_eq!(new_root, compute_root_from_leaves(&expected_leaves));
        assert!(winner.is_none());
    }

    #[test]
    fn full_board_draw() {
        let sk_x = signing_key(&[1u8; 32]);
        let pk_x = verifying_key(&[1u8; 32]);
        let pk_o = verifying_key(&[2u8; 32]);

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
        let move_x = PlayerMove::Play {
            pubkey: pk_x,
            coords: (2, 2),
        };

        let witness = Witness {
            leaves,
            signature: sign_move(&sk_x, &move_x, root),
        };

        let (_, _, winner) = stf(root, &move_x, &witness).expect("Draw move failed");
        assert!(winner.is_none(), "There should be no winner in a draw");
    }
    #[test]
    fn cell_already_occupied() {
        let sk_o = signing_key(&[2u8; 32]);
        let pk_x = verifying_key(&[1u8; 32]);
        let pk_o = verifying_key(&[2u8; 32]);

        let (_, mut leaves) = init_game(&pk_x, &pk_o);

        // X already at (0,0), it's O's turn
        leaves[0] = hash_leaf(Cell::X as u8);
        leaves[TURN_TRACKER_IDX] = hash_leaf(PlayerRole::O as u8);

        let root = compute_root_from_leaves(&leaves);

        let move_o = PlayerMove::Play {
            pubkey: pk_o,
            coords: (0, 0),
        };

        let witness = Witness {
            leaves,
            signature: sign_move(&sk_o, &move_o, root),
        };

        let result = stf(root, &move_o, &witness);

        assert_eq!(result.unwrap_err(), StfError::CellNotEmpty(0, 0));
    }
    #[test]
    fn invalid_merkle_witness() {
        let sk_x = signing_key(&[1u8; 32]);
        let pk_x = verifying_key(&[1u8; 32]);
        let pk_o = verifying_key(&[2u8; 32]);
        let (trusted_root, leaves) = init_game(&pk_x, &pk_o);

        let move_x = PlayerMove::Play {
            pubkey: pk_x,
            coords: (0, 0),
        };

        // Corrupt the witness by changing a padding leaf (index 15)
        let mut corrupt_leaves = leaves;
        corrupt_leaves[15] = hash_leaf(99);

        let witness = Witness {
            leaves: corrupt_leaves,
            signature: sign_move(&sk_x, &move_x, trusted_root),
        };

        let result = stf(trusted_root, &move_x, &witness);
        assert_eq!(result.unwrap_err(), StfError::InvalidMerkleProof);
    }

    #[test]
    fn invalid_signature_fails() {
        let sk_x = signing_key(&[1u8; 32]);
        let pk_x = verifying_key(&[1u8; 32]);
        let pk_o = verifying_key(&[2u8; 32]);
        let (root, leaves) = init_game(&pk_x, &pk_o);

        let move_x = PlayerMove::Play {
            pubkey: pk_x,
            coords: (0, 0),
        };

        let mut witness = Witness {
            leaves,
            signature: sign_move(&sk_x, &move_x, root),
        };

        // Corrupt the signature by flipping bits
        witness.signature[0] ^= 0xFF;

        let result = stf(root, &move_x, &witness);
        assert_eq!(result.unwrap_err(), StfError::InvalidSignature);
    }
}
