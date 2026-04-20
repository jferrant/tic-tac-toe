//! Entry point for the Tic-Tac-Toe game server.
//!
//! Starts the Axum HTTP server and registers three routes:
//! - `POST /game/create`     — initialize a new game
//! - `POST /game/play`       — submit a single authenticated move
//! - `POST /game/play_batch` — submit multiple moves in one request

use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

use axum::{routing::post, Router};

use server::{
    handlers::{handle_batch, handle_create, handle_play},
    state::AppState,
};

#[derive(Parser, Debug)]
#[command(author, version, about = "Tic-Tac-Toe Game Server")]
struct Args {
    /// Port to listen on
    #[arg(long, default_value_t = 3000)]
    port: u16,

    /// Host address to bind to
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
}

// Handle a shutdown more gracefully
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");

    println!("\n🛑 Attempting to shut down gracefully...");
}

#[tokio::main]
async fn main() {
    // Init logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Parse command line arguments
    let args = Args::parse();

    // Setup the shared game state
    let shared_state = Arc::new(AppState::default());

    let app = Router::new()
        .route("/game/create", post(handle_create))
        .route("/game/play", post(handle_play))
        .route("/game/play_batch", post(handle_batch))
        .with_state(shared_state);

    let addr: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .expect("Invalid host or port configuration");

    let listener = TcpListener::bind(addr).await.unwrap();

    println!("🚀 Server running on http://{addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}
