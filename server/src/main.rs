//! # Tic-Tac-Toe ZK-Server
//!
//! This crate will impelement the stateful coordinator and "Prover" for the
//! zkVM-provable Tic-Tac-Toe game. It will bridge the gap between signed user
//! actions and the pure State Transition Function (STF).

use std::sync::Arc;
use tracing::info;

use axum::{routing::post, Router};

use crate::{
    handlers::{handle_create, handle_play},
    state::AppState,
};
pub mod handlers;
pub mod models;
pub mod state;

#[tokio::main]
async fn main() {
    // Init logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let shared_state = Arc::new(AppState::default());

    let app = Router::new()
        .route("/game/create", post(handle_create))
        .route("/game/play", post(handle_play))
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    info!("Server listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}
