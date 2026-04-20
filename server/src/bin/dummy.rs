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

    // Setup Actors
    let alice = Arc::new(TestPlayer::new("Alice"));
    let bob = Arc::new(TestPlayer::new("Bob"));
    let charlie = Arc::new(TestPlayer::new("Charlie"));

    println!("🎭 Starting Parallel Multi-Game Stress Test with Malicious Actors...");

    // Channels to communicate real Game IDs to the Malicious Task
    let (tx1, rx1) = oneshot::channel(); // For Hijack Test
    let (tx2, rx2) = oneshot::channel(); // For Out-of-Turn Test

    // Define scripts
    let draw_script = vec![
        (0, 0),
        (0, 1),
        (0, 2),
        (1, 1),
        (1, 0),
        (1, 2),
        (2, 1),
        (2, 0),
        (2, 2),
    ];
    let bob_wins_script = vec![(0, 0), (1, 0), (0, 1), (1, 1), (0, 2)];
    let charlie_wins_script = vec![(0, 0), (1, 0), (0, 1), (1, 1), (0, 2)];
    let alice_wins_script = vec![(1, 0), (0, 0), (1, 1), (0, 1), (2, 2), (0, 2)];

    // Spawn concurrent games
    let handles = vec![
        spawn_game(
            client.clone(),
            base_url,
            alice.clone(),
            bob.clone(),
            draw_script,
            "GAME 1 (TIE)",
            Some(tx1),
        ),
        spawn_game(
            client.clone(),
            base_url,
            bob.clone(),
            charlie.clone(),
            bob_wins_script,
            "GAME 2 (BOB WINS)",
            Some(tx2),
        ),
        spawn_game(
            client.clone(),
            base_url,
            charlie.clone(),
            alice.clone(),
            charlie_wins_script,
            "GAME 3 (CHARLIE WINS)",
            None,
        ),
        spawn_game(
            client.clone(),
            base_url,
            bob.clone(),
            alice.clone(),
            alice_wins_script,
            "GAME 4 (ALICE WINS)",
            None,
        ),
    ];

    // --- MALICIOUS TASK ---
    let charlie_clone = charlie.clone();
    let client_clone = client.clone();

    let malicious_handle = tokio::spawn(async move {
        // CASE A: HIJACK ATTEMPT
        // Wait for Game 1 (Alice vs Bob) to be created
        if let Ok(target_gid) = rx1.await {
            // TODO: add a helper hear to make sure the game exists via some call to the server.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            println!("👿 [MALICIOUS] Charlie attempting to hijack Alice/Bob game ID: {target_gid}");

            let m = PlayerMove::Play {
                pubkey: charlie_clone.pk,
                coords: (2, 2),
            };
            let sig = charlie_clone
                .sk
                .sign(&format_auth_message(&m, [0u8; 32]))
                .to_vec();

            let req = PlayRequest {
                game_id: target_gid,
                x: 2,
                y: 2,
                pubkey: charlie_clone.pk,
                signature: sig,
            };

            let res = client_clone
                .post(format!("{base_url}/game/play"))
                .json(&req)
                .send()
                .await
                .unwrap();
            println!(
                "👿 [MALICIOUS] Hijack Result (Expected 400 InvalidPlayer): {}",
                res.status()
            );
        }

        // CASE B: OUT OF TURN ATTEMPT
        // Wait for Game 2 (Bob vs Charlie) to be created.
        // In Game 2, Bob is Player X (starts), Charlie is Player O.
        if let Ok(game2_id) = rx2.await {
            println!("👿 [MALICIOUS] Charlie attempting to move BEFORE Bob in Game 2...");

            // We need the starting root (empty board)
            let bob_pk = [0u8; 32]; // Not needed for the root calculation but for init
            let (_, start_leaves) = init_game(&bob_pk, &charlie_clone.pk);
            let start_root = compute_root_from_leaves(&start_leaves);

            let m = PlayerMove::Play {
                pubkey: charlie_clone.pk,
                coords: (1, 1),
            };
            let sig = charlie_clone
                .sk
                .sign(&format_auth_message(&m, start_root))
                .to_vec();

            let req = PlayRequest {
                game_id: game2_id,
                x: 1,
                y: 1,
                pubkey: charlie_clone.pk,
                signature: sig,
            };

            let res = client_clone
                .post(format!("{base_url}/game/play"))
                .json(&req)
                .send()
                .await
                .unwrap();
            println!(
                "👿 [MALICIOUS] Out-of-Turn Result (Expected 400 InvalidPlayer): {}",
                res.status()
            );
        }
    });

    // Join all
    for handle in handles {
        handle.await;
    }
    malicious_handle.await.unwrap();

    println!("\n🏁 All scenarios completed successfully!");
    Ok(())
}

async fn spawn_game(
    client: reqwest::Client,
    url: &'static str,
    p1: Arc<TestPlayer>,
    p2: Arc<TestPlayer>,
    moves: Vec<(usize, usize)>,
    label: &'static str,
    id_tx: Option<oneshot::Sender<u128>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Create Game
        let nonce = rand::random();
        let create_move = PlayerMove::CreateGame {
            pubkey_x: p1.pk,
            pubkey_y: p2.pk,
            nonce,
        };
        let create_sig = p1
            .sk
            .sign(&format_auth_message(&create_move, NULL_HASH))
            .to_vec();

        let create_req = CreateRequest {
            pubkey_x: p1.pk,
            pubkey_y: p2.pk,
            signature: create_sig,
            nonce,
        };
        let res = client
            .post(format!("{url}/game/create"))
            .json(&create_req)
            .send()
            .await
            .unwrap();
        let create_data: CreateResponse = res.json().await.unwrap();
        let gid = create_data.game_id;

        println!("[{label}] Created ID: {gid}");
        if let Some(tx) = id_tx {
            let _ = tx.send(gid);
        }

        let (_, mut current_leaves) = init_game(&p1.pk, &p2.pk);

        for (turn, coord) in moves.into_iter().enumerate() {
            // Add slight jitter so games interleave more realistically
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;

            let active_player = if turn % 2 == 0 { &p1 } else { &p2 };
            let current_root = compute_root_from_leaves(&current_leaves);

            let m = PlayerMove::Play {
                pubkey: active_player.pk,
                coords: coord,
            };
            let sig = active_player
                .sk
                .sign(&format_auth_message(&m, current_root))
                .to_vec();

            let play_req = PlayRequest {
                game_id: gid,
                x: coord.0,
                y: coord.1,
                pubkey: active_player.pk,
                signature: sig,
            };

            let play_res = client
                .post(format!("{url}/game/play"))
                .json(&play_req)
                .send()
                .await
                .unwrap();

            if play_res.status().is_success() {
                let data: PlayResponse = play_res.json().await.unwrap();
                current_leaves = data.new_leaves;
                if let Some(winner) = data.winner {
                    let winner_name = if winner == p1.pk { p1.name } else { p2.name };
                    println!("[{label}] 🏆 WINNER: {winner_name}");
                }
            } else {
                println!(
                    "[{label}] ❌ STOPPED at turn {}: {}",
                    turn,
                    play_res.status()
                );
                break;
            }
        }
        println!("[{label}] Finished.");
    })
}
