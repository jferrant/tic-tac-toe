use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use tracing::{info, warn};
use ttt_core::{
    logic::{stf, PlayerMove, Witness},
    merkle::{compute_root_from_leaves, NULL_HASH},
};

use crate::{
    models::{CreateRequest, CreateResponse, PlayRequest, PlayResponse},
    state::{generate_game_id, AppState},
};
pub async fn handle_create(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateRequest>,
) -> Result<Json<CreateResponse>, StatusCode> {
    let nonce = payload.nonce;
    let pubkey_x = payload.pubkey_x;
    let pubkey_y = payload.pubkey_y;
    let signature = payload.signature_bytes().map_err(|_| StatusCode::BAD_REQUEST)?;
    let core_move = PlayerMove::from(payload);
    
    // Setup the "Genesis" Witness
    // CreateGame is signed against NULL_HASH per our format_auth_message logic
    let initial_root = NULL_HASH; 
    let witness = Witness {
        leaves: [NULL_HASH; 16],
        signature,
    };

    // Let the STF verify the signature, the keys, and the nonce
    let (_genesis_root, new_leaves, _) = stf(initial_root, &core_move, &witness).map_err(|e| {
        warn!("STF rejected game creation: {e:?}");
        StatusCode::BAD_REQUEST
    })?;

    // Generate the ID and persist
    let game_id = generate_game_id(&pubkey_x, &pubkey_y, nonce);
    
    if state.game_exists(game_id) {
        return Err(StatusCode::CONFLICT);
    }

    state
        .create_game(game_id, new_leaves)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(CreateResponse { game_id }))
}

pub async fn handle_play(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PlayRequest>,
) -> Result<Json<PlayResponse>, StatusCode> {
    let gid = payload.game_id;
    let leaves = state.get_witness_data(gid).ok_or(StatusCode::NOT_FOUND)?;
    let prior_root = compute_root_from_leaves(&leaves);

    let sig_bytes = payload.signature_bytes().map_err(|_| StatusCode::BAD_REQUEST)?;
    let core_move = PlayerMove::from(payload);
    
    let witness = Witness { 
        leaves, 
        signature: sig_bytes 
    };

    // The STF does the heavy lifting:
    // - Verifies the signature against the prior_root
    // - Verifies it is actually this player's turn
    // - Verifies the move is valid (cell not occupied, etc)
    let (new_root, new_leaves, winner) = stf(prior_root, &core_move, &witness).map_err(|e| {
        warn!("STF rejected move for game {gid}: {e:?}");
        StatusCode::BAD_REQUEST
    })?;

    // Update the global state of the game
    state
        .update_game_state(gid, new_leaves)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some(winner_pk) = winner {
        info!("WINNER! {winner_pk:?} won game {gid}");
    }

    Ok(Json(PlayResponse { new_root, winner }))
}
