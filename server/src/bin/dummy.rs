use ed25519_dalek::{Signer, SigningKey};
use server::models::{CreateRequest, CreateResponse, PlayRequest, PlayResponse};
use std::sync::Arc;
use tokio::sync::oneshot;
use ttt_core::logic::{format_auth_message, init_game, PlayerMove};
use ttt_core::merkle::{compute_root_from_leaves, NULL_HASH};

struct TestPlayer {
    name: &'static str,
    sk: SigningKey,
    pk: [u8; 32],
}

impl TestPlayer {
    fn new(name: &'static str) -> Self {
        let mut rng = rand::thread_rng();
        let sk = SigningKey::generate(&mut rng);
        let pk = sk.verifying_key().to_bytes();
        Self { name, sk, pk }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let base_url = "http://127.0.0.1:3000";

    // Initialize Actors
    let alice = Arc::new(TestPlayer::new("Alice"));
    let bob = Arc::new(TestPlayer::new("Bob"));
    let charlie = Arc::new(TestPlayer::new("Charlie"));

    println!("🎭 Starting Parallel Multi-Game Stress Test...");

    // Channels to pass real Game IDs to the Malicious Task
    let (tx1, rx1) = oneshot::channel(); // For Hijack Test
    let (tx2, rx2) = oneshot::channel(); // For Out-of-Turn Test

    let draw_script = vec![
        (0,0), (0,1), (0,2), // Alice X, Bob O, Alice X
        (1,1), (1,0), (1,2), // Bob O, Alice X, Bob O
        (2,1), (2,0), (2,2)  // Alice X, Bob O, Alice X -> TIE
    ];
    let bob_wins_script = vec![
        (0,0), (1,0), (0,1), (1,1), (0,2) // Bob X takes Col 0
    ];
    let charlie_wins_script = vec![
        (0,0), (1,0), (0,1), (1,1), (0,2) // Charlie X takes Col 0
    ];
    let alice_wins_script = vec![
        (1,1), (0,0), (0,1), (1,0), (2,2), (2,0) // Alice O takes Col 0
    ];

    // Spawn all games simultaneously
    let handles = vec![
        spawn_game(client.clone(), base_url, alice.clone(), bob.clone(), draw_script, "GAME 1 (TIE)", Some(tx1)),
        spawn_game(client.clone(), base_url, bob.clone(), charlie.clone(), bob_wins_script, "GAME 2 (BOB WINS)", Some(tx2)),
        spawn_game(client.clone(), base_url, charlie.clone(), alice.clone(), charlie_wins_script, "GAME 3 (CHARLIE WINS)", None),
        spawn_game(client.clone(), base_url, bob.clone(), alice.clone(), alice_wins_script, "GAME 4 (ALICE WINS)", None),
    ];

    // Malicious Hijacker Task
    let charlie_clone = charlie.clone();
    let bob_pk = bob.pk; 
    let client_clone = client.clone();

    let malicious_handle = tokio::spawn(async move {
        // CASE A: Hijack Attempt (Wait for Game 1 ID)
        if let Ok(target_gid) = rx1.await {
            // TODO: add a helper hear to make sure the game exists via some call to the server.
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            println!("👿 [MALICIOUS] Charlie attempting to hijack Game {target_gid}...");
            let m = PlayerMove::Play { pubkey: charlie_clone.pk, coords: (2,2) };
            let sig = charlie_clone.sk.sign(&format_auth_message(&m, [0u8; 32])).to_vec();
            let req = PlayRequest { game_id: target_gid, x: 2, y: 2, pubkey: charlie_clone.pk, signature: sig };
            let res = client_clone.post(format!("{base_url}/game/play")).json(&req).send().await.unwrap();
            println!("👿 [MALICIOUS] Hijack Result: {}", res.status());
        }

        // CASE B: Out of Turn (Wait for Game 2 ID)
        if let Ok(game2_id) = rx2.await {
            println!("👿 [MALICIOUS] Charlie trying to move before Bob in Game {game2_id}...");
            let (_, start_leaves) = init_game(&bob_pk, &charlie_clone.pk);
            let start_root = compute_root_from_leaves(&start_leaves);
            let m = PlayerMove::Play { pubkey: charlie_clone.pk, coords: (1,1) };
            let sig = charlie_clone.sk.sign(&format_auth_message(&m, start_root)).to_vec();
            let req = PlayRequest { game_id: game2_id, x: 1, y: 1, pubkey: charlie_clone.pk, signature: sig };
            let res = client_clone.post(format!("{base_url}/game/play")).json(&req).send().await.unwrap();
            println!("👿 [MALICIOUS] Out-of-Turn Result: {}", res.status());
        }
    });

    // Await Everything Explicitly
    println!("⏳ Awaiting all game results...");
    for handle in handles {
        handle.await.unwrap();
    }
    let _ = malicious_handle.await;

    println!("\n🏁 All scenarios completed successfully!");
    Ok(())
}

fn spawn_game(
    client: reqwest::Client,
    url: &'static str,
    p1: Arc<TestPlayer>,
    p2: Arc<TestPlayer>,
    moves: Vec<(usize, usize)>,
    label: &'static str,
    id_tx: Option<oneshot::Sender<u128>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Create the games
        let nonce = rand::random();
        let create_move = PlayerMove::CreateGame { pubkey_x: p1.pk, pubkey_y: p2.pk, nonce };
        let create_sig = p1.sk.sign(&format_auth_message(&create_move, NULL_HASH)).to_vec();
        let create_req = CreateRequest { pubkey_x: p1.pk, pubkey_y: p2.pk, signature: create_sig, nonce };

        let res = client.post(format!("{url}/game/create")).json(&create_req).send().await.unwrap();
        let create_data: CreateResponse = res.json().await.expect("Create failed");
        let gid = create_data.game_id;
        
        println!("[{label}] 🚀 Created ID: {gid}");
        if let Some(tx) = id_tx { let _ = tx.send(gid).ok(); }

        let (_, mut current_leaves) = init_game(&p1.pk, &p2.pk);

        // Play the games in a loop for each move
        for (turn, coord) in moves.into_iter().enumerate() {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            let active_player = if turn % 2 == 0 { &p1 } else { &p2 };
            let current_root = compute_root_from_leaves(&current_leaves);

            let m = PlayerMove::Play { pubkey: active_player.pk, coords: coord };
            let sig = active_player.sk.sign(&format_auth_message(&m, current_root)).to_vec();

            let play_req = PlayRequest {
                game_id: gid, x: coord.0, y: coord.1,
                pubkey: active_player.pk, signature: sig,
            };

            let play_res = client.post(format!("{url}/game/play")).json(&play_req).send().await.unwrap();
            let status = play_res.status();

            if status.is_success() {
                let body = play_res.text().await.unwrap();
                let data: PlayResponse = serde_json::from_str(&body).expect("JSON Parse Error");
                
                current_leaves = data.new_leaves;
                println!("[{label}] Turn {turn}: {} played at ({}, {})", active_player.name, coord.0, coord.1);
                
                if let Some(winner_pk) = data.winner {
                    let name = if winner_pk == p1.pk { p1.name } else { p2.name };
                    println!("[{label}] 🏆 WINNER: {name}");
                    return; 
                }
            } else {
                let err = play_res.text().await.unwrap_or_default();
                println!("[{label}] ❌ REJECTED Turn {turn}: {status} | Server: {err}");
                return;
            }
        }
        println!("[{label}] 🤝 Reached end of script (No Winner).");
    })
}