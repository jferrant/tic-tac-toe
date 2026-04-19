use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use ed25519_dalek::{Verifier, VerifyingKey};
use tracing::{info, warn};
use ttt_core::{
    logic::{stf, PlayerMove, PlayerRole, Witness, TURN_TRACKER_IDX},
    merkle::{compute_root_from_leaves, hash_leaf, NULL_HASH},
};

use crate::{
    models::{CreateRequest, CreateResponse, PlayRequest, PlayResponse},
    state::{generate_game_id, AppState},
};

pub async fn handle_create(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateRequest>,
) -> Result<Json<CreateResponse>, StatusCode> {
    let message = format!(
        "CREATE_GAME:{:?}:{:?}:{}",
        payload.pubkey_x, payload.pubkey_y, payload.nonce
    );
    let public_key =
        VerifyingKey::from_bytes(&payload.pubkey_x).map_err(|_| StatusCode::BAD_REQUEST)?;

    let sig = payload
        .dalek_signature()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    public_key
        .verify(message.as_bytes(), &sig)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let game_id = generate_game_id(&payload.pubkey_x, &payload.pubkey_y, payload.nonce);

    // Prevent overwriting an existing game
    if state.game_exists(game_id) {
        return Err(StatusCode::CONFLICT);
    }
    let empty_leaves = [NULL_HASH; 16];
    let initial_root = compute_root_from_leaves(&empty_leaves);
    let witness = Witness {
        leaves: empty_leaves,
    };

    // Capture the pks before we move the payload
    let pk_x = payload.pubkey_x;
    let pk_y = payload.pubkey_y;
    let core_move = PlayerMove::from(payload);

    // FIX: Match the 3-tuple return (root, leaves, winner)
    let (_genesis_root, _) = stf(initial_root, &core_move, &witness).map_err(|e| {
        warn!("Failed to initialize game: {e:?}");
        StatusCode::BAD_REQUEST
    })?;

    state
        .create_game(game_id, &pk_x, &pk_y)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(CreateResponse { game_id }))
}

pub async fn handle_play(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PlayRequest>,
) -> Result<Json<PlayResponse>, StatusCode> {
    // Make sure we extract before consuming PlayRequest
    let gid = payload.game_id;
    let x = payload.x;
    let y = payload.y;

    // Get the prior root to verify the signature/pass to stf
    let leaves = state.get_witness_data(gid).ok_or(StatusCode::NOT_FOUND)?;
    let prior_root = compute_root_from_leaves(&leaves);

    // Make sure owner of pubkey actually sent this message and that its contents are as intended (no man in the middle)
    // Note that the stf is what will judge if it actually has authority within this game.
    let message = format!("{gid}-{x}-{y}-{prior_root:?}");
    let public_key =
        VerifyingKey::from_bytes(&payload.pubkey).map_err(|_| StatusCode::BAD_REQUEST)?;

    let sig = payload
        .dalek_signature()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    public_key
        .verify(message.as_bytes(), &sig)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Determine which player we are
    let current_role = if leaves[TURN_TRACKER_IDX] == hash_leaf(PlayerRole::X as u8) {
        PlayerRole::X
    } else {
        PlayerRole::O
    };

    let core_move = PlayerMove::from(payload);
    // make sure the STF is satisfied. This will also verify that not just any random pubkey is attempting
    // to make a move for either of our players.
    let (new_root, winner) =
        stf(prior_root, &core_move, &Witness { leaves }).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Update our game state
    state.apply_move(gid, x, y, current_role);

    if let Some(winner_pk) = winner {
        info!("WINNER! {winner_pk:?} won game {gid}");
    }

    Ok(Json(PlayResponse { new_root, winner }))
}
