use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use tracing::{info, warn};
use ttt_core::logic::{convert_coordinates_to_index, stf, Cell, PlayerMove, PlayerRole, Witness};
use ttt_core::merkle::NULL_HASH;

use crate::{
    models::{CreateRequest, CreateResponse, PlayRequest, PlayResponse},
    state::{generate_game_id, AppState, StoredGame},
};

pub async fn handle_create(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateRequest>,
) -> Result<Json<CreateResponse>, StatusCode> {
    let pubkey_x = payload.pubkey_x;
    let pubkey_y = payload.pubkey_y;
    let nonce = payload.nonce;
    // Exit early if we are attempting to generate an already existing game.
    let game_id = generate_game_id(&pubkey_x, &pubkey_y, nonce);
    if state.game_exists(game_id) {
        return Err(StatusCode::CONFLICT);
    }

    let signature = payload
        .signature_bytes()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let core_move = PlayerMove::from(payload);
    let witness = Witness::CreateGame { signature };

    let (new_root, _) = stf(NULL_HASH, &core_move, &witness).map_err(|e| {
        warn!("STF rejected game creation: {e:?}");
        StatusCode::BAD_REQUEST
    })?;

    let stored = StoredGame {
        root: new_root,
        board: [Cell::Empty; 9],
        turn: PlayerRole::X,
        pk_x: pubkey_x,
        pk_o: pubkey_y,
    };

    state
        .create_game(game_id, stored)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(CreateResponse { game_id }))
}

pub async fn handle_play(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PlayRequest>,
) -> Result<Json<PlayResponse>, StatusCode> {
    let gid = payload.game_id;
    let coord_x = payload.x;
    let coord_y = payload.y;
    let StoredGame {
        root: prior_root,
        turn,
        board,
        pk_x,
        pk_o,
    } = state.get_game(gid).ok_or(StatusCode::NOT_FOUND)?;

    let pubkey = payload.pubkey;
    let signature = payload
        .signature_bytes()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // The other player is whoever isn't making this move.
    let other_player_pubkey = if pubkey == pk_x { pk_o } else { pk_x };

    let core_move = PlayerMove::from(payload);
    let witness = Witness::Play {
        board,
        turn,
        other_player_pubkey,
        signature,
    };

    let (new_root, winner) = stf(prior_root, &core_move, &witness).map_err(|e| {
        warn!("STF rejected move for game {gid}: {e:?}");
        StatusCode::BAD_REQUEST
    })?;

    // Update server state independently: the STF verified the transition is valid.
    let board_idx =
        convert_coordinates_to_index(coord_x, coord_y).map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut new_board = board;
    new_board[board_idx] = match turn {
        PlayerRole::X => Cell::X,
        PlayerRole::O => Cell::O,
    };
    let new_turn = turn.next();

    state
        .update_game(gid, new_root, new_board, new_turn)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if winner.is_some() {
        info!("Game {gid} finished. WiINNER: {winner:?}");
    }

    Ok(Json(PlayResponse { new_root, winner }))
}
