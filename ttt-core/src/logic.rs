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

/// The minimal witness for a single STF execution.
///
/// **Witness sizes:**
/// - `CreateGame`: 64 bytes (signature only — prior state is always NULL_HASH)
/// - `Play`: 9 (board) + 1 (turn) + 32 (other player pubkey) + 64 (sig) = **106 bytes**
///
/// Compare to the naive approach of passing all 16 × 32-byte leaves (576 bytes total).
/// Savings come from:
/// - Storing raw `Cell` values (1 byte) instead of their SHA-256 hashes (32 bytes each)
/// - Omitting the current player's leaf (derived from `pubkey` already in the move)
/// - Omitting padding leaves 12–15  (always `NULL_HASH`, fully deterministic)
/// - Folding identity verification into the root check (wrong pubkey means wrong root)
pub enum Witness {
    CreateGame {
        signature: [u8; 64],
    },
    Play {
        /// Raw board values (9 bytes instead of 9 × 32-byte hashes)
        board: [Cell; 9],
        /// Whose turn it currently is (1 byte instead of a 32-byte hash)
        turn: PlayerRole,
        /// The OTHER player's raw pubkey, needed only to reconstruct the Merkle root.
        /// The current player's pubkey comes from the `PlayerMove` itself.
        other_player_pubkey: Player,
        signature: [u8; 64],
    },
}

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

/// Reconstruct all 16 Merkle leaves from compact witness data.
///
/// The current player's leaf is derived from `current_pubkey` (present in the move).
/// The other player's leaf is derived from `other_pubkey` (in the witness).
/// Padding leaves 12–15 default to `NULL_HASH`.
fn build_leaves(
    current_pubkey: &Player,
    other_pubkey: &Player,
    board: &[Cell; 9],
    turn: PlayerRole,
) -> [Hash; 16] {
    let mut leaves = [NULL_HASH; 16];
    for (i, cell) in board.iter().enumerate() {
        leaves[i] = hash_leaf(*cell as u8);
    }
    let current_leaf = hash_leaf_from_hash(hash_bytes(current_pubkey));
    let other_leaf = hash_leaf_from_hash(hash_bytes(other_pubkey));
    match turn {
        PlayerRole::X => {
            leaves[PLAYER_X_IDX] = current_leaf;
            leaves[PLAYER_O_IDX] = other_leaf;
        }
        PlayerRole::O => {
            leaves[PLAYER_X_IDX] = other_leaf;
            leaves[PLAYER_O_IDX] = current_leaf;
        }
    }
    leaves[TURN_TRACKER_IDX] = hash_leaf(turn as u8);
    leaves
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

/// Pure State Transition Function.
///
/// Returns `(new_merkle_root, Option<winner_pubkey>)`.
///
/// For `Play`, identity verification is folded into the root check: providing the
/// wrong pubkey (wrong player, wrong turn) produces a different root, which fails
/// the `compute_root_from_leaves(...) != prior_merkle_root_hash` check. No separate
/// identity comparison is needed.
pub fn stf(
    prior_merkle_root_hash: Hash,
    player_move: &PlayerMove,
    witness: &Witness,
) -> Result<(Hash, Option<Winner>), StfError> {
    match (player_move, witness) {
        (
            PlayerMove::CreateGame {
                pubkey_x, pubkey_y, ..
            },
            Witness::CreateGame { signature },
        ) => {
            let message = format_auth_message(player_move, prior_merkle_root_hash);
            verify_signature(pubkey_x, &message, signature)?;

            if prior_merkle_root_hash != NULL_HASH {
                return Err(StfError::GameAlreadyInitialized);
            }
            if pubkey_x == pubkey_y {
                return Err(StfError::IdenticalPlayerKeys);
            }
            let (new_root, _) = init_game(pubkey_x, pubkey_y);
            Ok((new_root, None))
        }
        (
            PlayerMove::Play { pubkey, coords },
            Witness::Play {
                board,
                turn,
                other_player_pubkey,
                signature,
            },
        ) => {
            let message = format_auth_message(player_move, prior_merkle_root_hash);
            verify_signature(pubkey, &message, signature)?;

            if prior_merkle_root_hash == NULL_HASH {
                return Err(StfError::GameNotInitialized);
            }

            // Build leaves and verify root. This single check simultaneously verifies:
            // - The board state is correct
            // - The turn tracker is correct
            // - The current player's pubkey matches the registered player for this turn
            let leaves = build_leaves(pubkey, other_player_pubkey, board, *turn);
            if compute_root_from_leaves(&leaves) != prior_merkle_root_hash {
                return Err(StfError::InvalidMerkleProof);
            }

            if check_winner(&leaves).is_some() {
                return Err(StfError::GameAlreadyFinished);
            }

            let board_idx = convert_coordinates_to_index(coords.0, coords.1)?;
            if board[board_idx] != Cell::Empty {
                return Err(StfError::CellNotEmpty(coords.0, coords.1));
            }

            let mut new_leaves = leaves;
            new_leaves[board_idx] = hash_leaf(*turn as u8);
            new_leaves[TURN_TRACKER_IDX] = hash_leaf(turn.next() as u8);

            let winner = if let Some(winner_role) = check_winner(&new_leaves) {
                if winner_role != *turn {
                    return Err(StfError::InvalidState);
                }
                Some(*pubkey)
            } else {
                None
            };

            Ok((compute_root_from_leaves(&new_leaves), winner))
        }
        _ => Err(StfError::InvalidMerkleProof),
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

    fn root_for(pk_x: &Player, pk_o: &Player, board: &[Cell; 9], turn: PlayerRole) -> Hash {
        compute_root_from_leaves(&build_leaves(pk_x, pk_o, board, turn))
    }

    #[test]
    fn win_detection_and_locking() {
        let sk_x = signing_key(&[1u8; 32]);
        let sk_o = signing_key(&[2u8; 32]);
        let pk_x = verifying_key(&[1u8; 32]);
        let pk_o = verifying_key(&[2u8; 32]);

        // Board: [X, X, _, ...], X to play at (2, 0) for the win
        let board = [
            Cell::X,
            Cell::X,
            Cell::Empty,
            Cell::Empty,
            Cell::Empty,
            Cell::Empty,
            Cell::Empty,
            Cell::Empty,
            Cell::Empty,
        ];
        let prior_root = root_for(&pk_x, &pk_o, &board, PlayerRole::X);

        let move_x = PlayerMove::Play {
            pubkey: pk_x,
            coords: (2, 0),
        };
        let witness = Witness::Play {
            board,
            turn: PlayerRole::X,
            other_player_pubkey: pk_o,
            signature: sign_move(&sk_x, &move_x, prior_root),
        };

        let (new_root, winner) = stf(prior_root, &move_x, &witness).expect("Winning move failed");
        assert_eq!(winner, Some(pk_x));

        // O tries to move after X has won
        let won_board = [
            Cell::X,
            Cell::X,
            Cell::X,
            Cell::Empty,
            Cell::Empty,
            Cell::Empty,
            Cell::Empty,
            Cell::Empty,
            Cell::Empty,
        ];
        let move_o = PlayerMove::Play {
            pubkey: pk_o,
            coords: (0, 1),
        };
        let won_witness = Witness::Play {
            board: won_board,
            turn: PlayerRole::O,
            other_player_pubkey: pk_x,
            signature: sign_move(&sk_o, &move_o, new_root),
        };

        assert_eq!(
            stf(new_root, &move_o, &won_witness).unwrap_err(),
            StfError::GameAlreadyFinished
        );
    }

    #[test]
    fn check_invalid_player_identity() {
        let pk_x = verifying_key(&[1u8; 32]);
        let pk_o = verifying_key(&[2u8; 32]);
        let sk_attacker = signing_key(&[9u8; 32]);
        let attacker_pk = verifying_key(&[9u8; 32]);

        let board = [Cell::Empty; 9];
        let prior_root = root_for(&pk_x, &pk_o, &board, PlayerRole::X);

        let move_attack = PlayerMove::Play {
            pubkey: attacker_pk,
            coords: (0, 0),
        };
        // Attacker claims to be the current player but their pubkey doesn't match the root
        let witness = Witness::Play {
            board,
            turn: PlayerRole::X,
            other_player_pubkey: pk_o,
            signature: sign_move(&sk_attacker, &move_attack, prior_root),
        };

        assert_eq!(
            stf(prior_root, &move_attack, &witness).unwrap_err(),
            StfError::InvalidMerkleProof
        );
    }

    #[test]
    fn wrong_turn_order() {
        let sk_x = signing_key(&[1u8; 32]);
        let pk_x = verifying_key(&[1u8; 32]);
        let pk_o = verifying_key(&[2u8; 32]);

        let board = [Cell::Empty; 9];
        // Prior state: it is O's turn
        let prior_root = root_for(&pk_o, &pk_x, &board, PlayerRole::O);

        // X submits a witness claiming it's X's turn — root won't match
        let move_x = PlayerMove::Play {
            pubkey: pk_x,
            coords: (0, 0),
        };
        let witness = Witness::Play {
            board,
            turn: PlayerRole::X,
            other_player_pubkey: pk_o,
            signature: sign_move(&sk_x, &move_x, prior_root),
        };

        assert_eq!(
            stf(prior_root, &move_x, &witness).unwrap_err(),
            StfError::InvalidMerkleProof
        );
    }

    #[test]
    fn coordinate_boundary() {
        let sk_x = signing_key(&[1u8; 32]);
        let pk_x = verifying_key(&[1u8; 32]);
        let pk_o = verifying_key(&[2u8; 32]);

        let board = [Cell::Empty; 9];
        let prior_root = root_for(&pk_x, &pk_o, &board, PlayerRole::X);

        let move_bad = PlayerMove::Play {
            pubkey: pk_x,
            coords: (3, 0),
        };
        let witness = Witness::Play {
            board,
            turn: PlayerRole::X,
            other_player_pubkey: pk_o,
            signature: sign_move(&sk_x, &move_bad, prior_root),
        };

        assert_eq!(
            stf(prior_root, &move_bad, &witness).unwrap_err(),
            StfError::OutOfBounds(3, 0)
        );
    }

    #[test]
    fn successful_move_and_turn_toggle() {
        let sk_x = signing_key(&[1u8; 32]);
        let pk_x = verifying_key(&[1u8; 32]);
        let pk_o = verifying_key(&[2u8; 32]);

        let board = [Cell::Empty; 9];
        let prior_root = root_for(&pk_x, &pk_o, &board, PlayerRole::X);

        let move_x = PlayerMove::Play {
            pubkey: pk_x,
            coords: (0, 0),
        };
        let witness = Witness::Play {
            board,
            turn: PlayerRole::X,
            other_player_pubkey: pk_o,
            signature: sign_move(&sk_x, &move_x, prior_root),
        };

        let (new_root, winner) = stf(prior_root, &move_x, &witness).expect("X move failed");
        assert!(winner.is_none());

        // Verify the new root matches what we'd expect for the updated state
        let mut expected_board = board;
        expected_board[0] = Cell::X;
        let expected_root = root_for(&pk_o, &pk_x, &expected_board, PlayerRole::O);
        assert_eq!(new_root, expected_root);
    }

    #[test]
    fn full_board_draw() {
        let sk_x = signing_key(&[1u8; 32]);
        let pk_x = verifying_key(&[1u8; 32]);
        let pk_o = verifying_key(&[2u8; 32]);

        // X O X
        // X O O
        // O X _  <- X plays (2, 2) for the draw
        let board = [
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
        let prior_root = root_for(&pk_x, &pk_o, &board, PlayerRole::X);

        let move_x = PlayerMove::Play {
            pubkey: pk_x,
            coords: (2, 2),
        };
        let witness = Witness::Play {
            board,
            turn: PlayerRole::X,
            other_player_pubkey: pk_o,
            signature: sign_move(&sk_x, &move_x, prior_root),
        };

        let (_, winner) = stf(prior_root, &move_x, &witness).expect("Draw move failed");
        assert!(winner.is_none());
    }

    #[test]
    fn cell_already_occupied() {
        let sk_o = signing_key(&[2u8; 32]);
        let pk_x = verifying_key(&[1u8; 32]);
        let pk_o = verifying_key(&[2u8; 32]);

        // X has already played at (0, 0), O tries the same cell
        let board = [
            Cell::X,
            Cell::Empty,
            Cell::Empty,
            Cell::Empty,
            Cell::Empty,
            Cell::Empty,
            Cell::Empty,
            Cell::Empty,
            Cell::Empty,
        ];
        let prior_root = root_for(&pk_o, &pk_x, &board, PlayerRole::O);

        let move_o = PlayerMove::Play {
            pubkey: pk_o,
            coords: (0, 0),
        };
        let witness = Witness::Play {
            board,
            turn: PlayerRole::O,
            other_player_pubkey: pk_x,
            signature: sign_move(&sk_o, &move_o, prior_root),
        };

        assert_eq!(
            stf(prior_root, &move_o, &witness).unwrap_err(),
            StfError::CellNotEmpty(0, 0)
        );
    }

    #[test]
    fn invalid_merkle_witness() {
        let sk_x = signing_key(&[1u8; 32]);
        let pk_x = verifying_key(&[1u8; 32]);
        let pk_o = verifying_key(&[2u8; 32]);

        let board = [Cell::Empty; 9];
        let (trusted_root, _) = init_game(&pk_x, &pk_o);

        let move_x = PlayerMove::Play {
            pubkey: pk_x,
            coords: (0, 0),
        };
        // Provide a tampered board that doesn't match trusted_root
        let mut bad_board = board;
        bad_board[5] = Cell::X;
        let witness = Witness::Play {
            board: bad_board,
            turn: PlayerRole::X,
            other_player_pubkey: pk_o,
            signature: sign_move(&sk_x, &move_x, trusted_root),
        };

        assert_eq!(
            stf(trusted_root, &move_x, &witness).unwrap_err(),
            StfError::InvalidMerkleProof
        );
    }

    #[test]
    fn invalid_signature_fails() {
        let sk_x = signing_key(&[1u8; 32]);
        let pk_x = verifying_key(&[1u8; 32]);
        let pk_o = verifying_key(&[2u8; 32]);

        let board = [Cell::Empty; 9];
        let prior_root = root_for(&pk_x, &pk_o, &board, PlayerRole::X);

        let move_x = PlayerMove::Play {
            pubkey: pk_x,
            coords: (0, 0),
        };
        let mut sig = sign_move(&sk_x, &move_x, prior_root);
        sig[0] ^= 0xFF;

        let witness = Witness::Play {
            board,
            turn: PlayerRole::X,
            other_player_pubkey: pk_o,
            signature: sig,
        };

        assert_eq!(
            stf(prior_root, &move_x, &witness).unwrap_err(),
            StfError::InvalidSignature
        );
    }
}
