use ed25519_dalek::{Signer, SigningKey};
use server::models::{
    BatchMoveRequest, BatchRequest, BatchResponse, CreateRequest, CreateResponse, PlayRequest,
    PlayResponse,
};
use std::sync::Arc;
use tokio::sync::oneshot;
use ttt_core::logic::{
    PlayerMove, PlayerRole, TURN_TRACKER_IDX, convert_coordinates_to_index, format_auth_message, init_game
};
use ttt_core::merkle::{compute_root_from_leaves, hash_leaf, NULL_HASH};

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
        (0, 0),
        (0, 1),
        (0, 2), // Alice X, Bob O, Alice X
        (1, 1),
        (1, 0),
        (1, 2), // Bob O, Alice X, Bob O
        (2, 1),
        (2, 0),
        (2, 2), // Alice X, Bob O, Alice X -> TIE
    ];
    let bob_wins_script = vec![
        (0, 0),
        (1, 0),
        (0, 1),
        (1, 1),
        (0, 2), // Bob X takes Col 0
    ];
    let charlie_wins_script = vec![
        (0, 0),
        (1, 0),
        (0, 1),
        (1, 1),
        (0, 2), // Charlie X takes Col 0
    ];
    let alice_wins_script = vec![
        (1, 1),
        (0, 0),
        (0, 1),
        (1, 0),
        (2, 2),
        (2, 0), // Alice O takes Col 0
    ];

    let mut handles = vec![
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
            println!("👿 [MALICIOUS] Hijack Result: {}", res.status());
        }

        // CASE B: Out of Turn (Wait for Game 2 ID)
        if let Ok(game2_id) = rx2.await {
            println!("👿 [MALICIOUS] Charlie trying to move out of turn in Game {game2_id}...");
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
            println!("👿 [MALICIOUS] Out-of-Turn Result: {}", res.status());
        }
    });

    println!("⏳ Awaiting individual game results...");
    for handle in handles.drain(..) {
        handle.await.unwrap();
    }
    let _ = malicious_handle.await;

    // Batch move tests
    println!("\n🗂️  Starting Batch Move Tests...");

    // Alice (X) wins via top row in a single batch
    let alice_wins_batch = vec![(0, 0), (0, 1), (1, 0), (1, 1), (2, 0)];

    // Full 9-move draw, sent as one batch
    let draw_batch = vec![
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

    // Partial batch: first 3 moves only (no winner yet)
    let partial_batch = vec![(1, 1), (0, 0), (2, 2)];

    let batch_handles = vec![
        spawn_batch_game(
            client.clone(),
            base_url,
            alice.clone(),
            bob.clone(),
            alice_wins_batch,
            "BATCH 1 (ALICE WINS)",
        ),
        spawn_batch_game(
            client.clone(),
            base_url,
            bob.clone(),
            charlie.clone(),
            draw_batch,
            "BATCH 2 (DRAW)",
        ),
        spawn_batch_game(
            client.clone(),
            base_url,
            charlie.clone(),
            alice.clone(),
            partial_batch,
            "BATCH 3 (PARTIAL - no winner yet)",
        ),
        spawn_malicious_batch(client.clone(), base_url, alice.clone(), bob.clone(), charlie.clone()),
    ];

    println!("⏳ Awaiting batch results...");
    for handle in batch_handles {
        handle.await.unwrap();
    }

    println!("\n🏁 All scenarios completed!");
    Ok(())
}

/// Pre-sign all moves locally against the evolving Merkle root, then POST them all
/// at once to /game/play_batch. This is the core of the batch efficiency argument:
/// the per-move witness shrinks from 106 bytes to 72 bytes (coords + sig only).
fn spawn_batch_game(
    client: reqwest::Client,
    url: &'static str,
    p1: Arc<TestPlayer>,
    p2: Arc<TestPlayer>,
    moves: Vec<(usize, usize)>,
    label: &'static str,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Create the game
        let nonce: u128 = rand::random();
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
        let gid: u128 = res.json::<CreateResponse>().await.expect("Create failed").game_id;
        println!("[{label}] 🚀 Created batch game: {gid}");

        // Simulate state transitions locally to pre-sign each move.
        // Each move signs against the root *before* it is applied, matching
        // what batch_stf expects when it verifies each signature in sequence.
        let (_, mut leaves) = init_game(&p1.pk, &p2.pk);
        let mut current_root = compute_root_from_leaves(&leaves);
        let mut turn = PlayerRole::X;
        let mut batch_moves: Vec<BatchMoveRequest> = Vec::new();

        for &(x, y) in &moves {
            let (active_pk, active_sk) = match turn {
                PlayerRole::X => (p1.pk, &p1.sk),
                PlayerRole::O => (p2.pk, &p2.sk),
            };

            let m = PlayerMove::Play {
                pubkey: active_pk,
                coords: (x, y),
            };
            let sig = active_sk
                .sign(&format_auth_message(&m, current_root))
                .to_vec();

            // Advance local state: update the played cell and the turn tracker.
            let board_idx = convert_coordinates_to_index(x, y).unwrap();
            leaves[board_idx] = hash_leaf(turn as u8);
            let next_turn = turn.next();
            leaves[TURN_TRACKER_IDX] = hash_leaf(next_turn as u8);
            current_root = compute_root_from_leaves(&leaves);

            batch_moves.push(BatchMoveRequest { x, y, signature: sig });
            turn = next_turn;
        }

        let batch_req = BatchRequest {
            game_id: gid,
            moves: batch_moves,
        };
        let res = client
            .post(format!("{url}/game/play_batch"))
            .json(&batch_req)
            .send()
            .await
            .unwrap();
        let status = res.status();

        if status.is_success() {
            let data: BatchResponse = res.json().await.expect("Batch JSON parse error");
            if let Some(winner_pk) = data.winner {
                let name = if winner_pk == p1.pk { p1.name } else { p2.name };
                println!("[{label}] 🏆 BATCH WINNER: {name}!");
            } else {
                println!("[{label}] 🤝 Batch complete — no winner.");
            }
        } else {
            let err = res.text().await.unwrap_or_default();
            println!("[{label}] ❌ Batch REJECTED: {status} | {err}");
        }
    })
}

/// Verifies that a batch containing a move signed by the wrong player is rejected.
fn spawn_malicious_batch(
    client: reqwest::Client,
    url: &'static str,
    p1: Arc<TestPlayer>,
    p2: Arc<TestPlayer>,
    attacker: Arc<TestPlayer>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let nonce: u128 = rand::random();
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
        let gid = res.json::<CreateResponse>().await.expect("Create failed").game_id;

        // Build a 2-move batch: first move is legitimate (p1 at (0,0)),
        // second move has the attacker's signature instead of p2's.
        let (_, mut leaves) = init_game(&p1.pk, &p2.pk);
        let mut current_root = compute_root_from_leaves(&leaves);

        // Legitimate move 0 by p1
        let m0 = PlayerMove::Play {
            pubkey: p1.pk,
            coords: (0, 0),
        };
        let sig0 = p1.sk.sign(&format_auth_message(&m0, current_root)).to_vec();
        leaves[0] = hash_leaf(PlayerRole::X as u8);
        leaves[TURN_TRACKER_IDX] = hash_leaf(PlayerRole::O as u8);
        current_root = compute_root_from_leaves(&leaves);

        // Move 1: attacker signs with their key instead of p2's key
        let m1_legit = PlayerMove::Play {
            pubkey: p2.pk,
            coords: (1, 1),
        };
        let sig1_bad = attacker
            .sk
            .sign(&format_auth_message(&m1_legit, current_root))
            .to_vec();

        let batch_req = BatchRequest {
            game_id: gid,
            moves: vec![
                BatchMoveRequest { x: 0, y: 0, signature: sig0 },
                BatchMoveRequest { x: 1, y: 1, signature: sig1_bad },
            ],
        };

        let res = client
            .post(format!("{url}/game/play_batch"))
            .json(&batch_req)
            .send()
            .await
            .unwrap();
        let status = res.status();
        println!(
            "👿 [MALICIOUS BATCH] Attacker ({}) injected move 1 — server responded: {status}",
            attacker.name
        );
        assert!(
            status.is_client_error(),
            "Malicious batch should have been rejected!"
        );
    })
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
        let create_data: CreateResponse = res.json().await.expect("Create failed");
        let gid = create_data.game_id;

        println!("[{label}] 🚀 Created ID: {gid}");
        if let Some(tx) = id_tx {
            let _ = tx.send(gid);
        }

        let (_, init_leaves) = init_game(&p1.pk, &p2.pk);
        let mut current_root = compute_root_from_leaves(&init_leaves);

        for (turn, coord) in moves.into_iter().enumerate() {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            let active_player = if turn % 2 == 0 { &p1 } else { &p2 };
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
            let status = play_res.status();

            if status.is_success() {
                let body = play_res.text().await.unwrap();
                let data: PlayResponse = serde_json::from_str(&body).expect("JSON parse error");

                current_root = data.new_root;
                println!(
                    "[{label}] Turn {turn}: {} played at ({}, {})",
                    active_player.name, coord.0, coord.1
                );

                if let Some(winner_pk) = data.winner {
                    let name = if winner_pk == p1.pk { p1.name } else { p2.name };
                    println!("[{label}] 🏆 WINNER: {name}!");
                    return;
                }
            } else {
                let err = play_res.text().await.unwrap_or_default();
                println!("[{label}] ❌ REJECTED Turn {turn}: {status} | {err}");
                return;
            }
        }
        println!("[{label}] 🤝 Draw — no winner.");
    })
}
