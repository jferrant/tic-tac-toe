use ed25519_dalek::{Signer, SigningKey};
use server::models::{CreateRequest, CreateResponse, PlayRequest, PlayResponse};
use ttt_core::logic::{format_auth_message, init_game, PlayerMove};
use ttt_core::merkle::{compute_root_from_leaves, NULL_HASH};

#[tokio::main]
async fn main() {
    println!("🧪 Running test scenario...");
    if let Err(e) = run_test_scenario().await {
        eprintln!("❌ Failed: {e:?}");
    } else {
        println!("✅ Success!");
    }
}

pub async fn run_test_scenario() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let base_url = "http://127.0.0.1:3000";

    // Setup some identities
    let mut rng = rand::thread_rng();
    let alice_sk = SigningKey::generate(&mut rng);
    let alice_pk = alice_sk.verifying_key().to_bytes();

    let bob_sk = SigningKey::generate(&mut rng);
    let bob_pk = bob_sk.verifying_key().to_bytes();

    println!("🔑 Alice PK: {}", hex::encode(alice_pk));
    println!("🔑 Bob PK:   {}", hex::encode(bob_pk));

    // Create a game
    let nonce: u128 = rand::random();
    let create_move = PlayerMove::CreateGame {
        pubkey_x: alice_pk,
        pubkey_y: bob_pk,
        nonce,
    };

    // CreateGame is signed against NULL_HASH per our STF rules
    let create_msg = format_auth_message(&create_move, NULL_HASH);
    let create_sig = alice_sk.sign(&create_msg).to_vec();

    let create_req = CreateRequest {
        pubkey_x: alice_pk,
        pubkey_y: bob_pk,
        signature: create_sig,
        nonce,
    };

    let resp = client
        .post(format!("{base_url}/game/create"))
        .json(&create_req)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let err = resp.text().await?;
        return Err(format!("Create Game Failed ({status}): {}", err).into());
    }

    let create_data: CreateResponse = resp.json().await?;
    let game_id = create_data.game_id;
    println!("✅ Game Created! ID: {game_id}");

    // TRY (Alice at 1,1)
    // CRITICAL: We must sign against the root of the "New Game" state.
    // Since handle_create uses init_game(), we calculate that same root here.
    let (_, start_leaves) = init_game(&alice_pk, &bob_pk);
    let current_root = compute_root_from_leaves(&start_leaves);

    let play_move = PlayerMove::Play {
        pubkey: alice_pk,
        coords: (1, 1),
    };

    // Format message with the real current_root
    let play_msg = format_auth_message(&play_move, current_root);
    let play_sig = alice_sk.sign(&play_msg).to_vec();

    let play_req = PlayRequest {
        game_id,
        x: 1,
        y: 1,
        pubkey: alice_pk,
        signature: play_sig,
    };

    println!("🛰️ Sending move: Alice at (1,1)...");
    let resp = client
        .post(format!("{base_url}/game/play"))
        .json(&play_req)
        .send()
        .await?;

    let status = resp.status();
    if status.is_success() {
        let play_data: PlayResponse = resp.json().await?;
        println!("✅ Move accepted!");
        println!("🌲 New Merkle Root: {}", hex::encode(play_data.new_root));
    } else {
        let err_body = resp.text().await?;
        println!("❌ Play Failed Status: {status}");
        println!("📜 Server says: {err_body}");
        return Err("Move rejected by STF".into());
    }

    Ok(())
}
