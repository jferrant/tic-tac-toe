use ed25519_dalek::{Signer, SigningKey};
use server::models::{
    BatchMoveRequest, BatchRequest, BatchResponse, CreateRequest, CreateResponse, PlayRequest,
    PlayResponse,
};
use std::sync::Arc;
use tokio::sync::oneshot;
use ttt_core::logic::{
    convert_coordinates_to_index, format_auth_message, init_game, PlayerMove, PlayerRole,
    TURN_TRACKER_IDX,
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

/// Create a game on the server and return its ID.
async fn create_game(
    client: &reqwest::Client,
    url: &str,
    p1: &TestPlayer,
    p2: &TestPlayer,
) -> u128 {
    let nonce: u128 = rand::random();
    let m = PlayerMove::CreateGame {
        pubkey_x: p1.pk,
        pubkey_y: p2.pk,
        nonce,
    };
    let sig = p1.sk.sign(&format_auth_message(&m, NULL_HASH)).to_vec();
    let req = CreateRequest {
        pubkey_x: p1.pk,
        pubkey_y: p2.pk,
        signature: sig,
        nonce,
    };
    client
        .post(format!("{url}/game/create"))
        .json(&req)
        .send()
        .await
        .unwrap()
        .json::<CreateResponse>()
        .await
        .expect("Create failed")
        .game_id
}

/// Pre-sign a sequence of moves against the evolving Merkle root so they can be
/// submitted as a single batch. Each move commits to the root *before* it is applied,
/// matching what `batch_stf` expects when verifying signatures in sequence.
fn presign_batch(
    p1: &TestPlayer,
    p2: &TestPlayer,
    moves: &[(usize, usize)],
) -> Vec<BatchMoveRequest> {
    let (_, mut leaves) = init_game(&p1.pk, &p2.pk);
    let mut current_root = compute_root_from_leaves(&leaves);
    let mut turn = PlayerRole::X;

    moves
        .iter()
        .map(|&(x, y)| {
            let (pk, sk) = match turn {
                PlayerRole::X => (p1.pk, &p1.sk),
                PlayerRole::O => (p2.pk, &p2.sk),
            };
            let m = PlayerMove::Play {
                pubkey: pk,
                coords: (x, y),
            };
            let signature = sk.sign(&format_auth_message(&m, current_root)).to_vec();

            leaves[convert_coordinates_to_index(x, y).unwrap()] = hash_leaf(turn as u8);
            let next = turn.next();
            leaves[TURN_TRACKER_IDX] = hash_leaf(next as u8);
            current_root = compute_root_from_leaves(&leaves);
            turn = next;

            BatchMoveRequest { x, y, signature }
        })
        .collect()
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
        let gid = create_game(&client, url, &p1, &p2).await;
        println!("[{label}] 🚀 Created ID: {gid}");
        if let Some(tx) = id_tx {
            let _ = tx.send(gid);
        }

        let (_, init_leaves) = init_game(&p1.pk, &p2.pk);
        let mut current_root = compute_root_from_leaves(&init_leaves);

        for (turn_idx, coord) in moves.into_iter().enumerate() {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            let active = if turn_idx % 2 == 0 { &p1 } else { &p2 };
            let m = PlayerMove::Play {
                pubkey: active.pk,
                coords: coord,
            };
            let sig = active
                .sk
                .sign(&format_auth_message(&m, current_root))
                .to_vec();
            let req = PlayRequest {
                game_id: gid,
                x: coord.0,
                y: coord.1,
                pubkey: active.pk,
                signature: sig,
            };

            let res = client
                .post(format!("{url}/game/play"))
                .json(&req)
                .send()
                .await
                .unwrap();
            let status = res.status();

            if status.is_success() {
                let data: PlayResponse = res.json().await.expect("JSON parse error");
                current_root = data.new_root;
                println!(
                    "[{label}] Turn {turn_idx}: {} played at ({}, {})",
                    active.name, coord.0, coord.1
                );
                if let Some(winner_pk) = data.winner {
                    let name = if winner_pk == p1.pk { p1.name } else { p2.name };
                    println!("[{label}] 🏆 WINNER: {name}!");
                    return;
                }
            } else {
                println!(
                    "[{label}] ❌ REJECTED Turn {turn_idx}: {status} | {}",
                    res.text().await.unwrap_or_default()
                );
                return;
            }
        }
        println!("[{label}] 🤝 Draw — no winner.");
    })
}

fn spawn_batch_game(
    client: reqwest::Client,
    url: &'static str,
    p1: Arc<TestPlayer>,
    p2: Arc<TestPlayer>,
    moves: Vec<(usize, usize)>,
    label: &'static str,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let gid = create_game(&client, url, &p1, &p2).await;
        println!("[{label}] 🚀 Created batch game: {gid}");

        let batch_moves = presign_batch(&p1, &p2, &moves);
        let req = BatchRequest {
            game_id: gid,
            moves: batch_moves,
        };
        let res = client
            .post(format!("{url}/game/play_batch"))
            .json(&req)
            .send()
            .await
            .unwrap();
        let status = res.status();

        if status.is_success() {
            let data: BatchResponse = res.json().await.expect("Batch JSON parse error");
            match data.winner {
                Some(pk) => {
                    let name = if pk == p1.pk { p1.name } else { p2.name };
                    println!("[{label}] 🏆 BATCH WINNER: {name}!");
                }
                None => println!("[{label}] 🤝 Batch complete — no winner."),
            }
        } else {
            println!(
                "[{label}] ❌ Batch REJECTED: {status} | {}",
                res.text().await.unwrap_or_default()
            );
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
        let gid = create_game(&client, url, &p1, &p2).await;

        // Move 0: legitimate (p1 signs correctly).
        // Move 1: attacker injects their signature instead of p2's.
        let mut legit = presign_batch(&p1, &p2, &[(0, 0), (1, 1)]);
        let (_, mut leaves) = init_game(&p1.pk, &p2.pk);
        leaves[0] = hash_leaf(PlayerRole::X as u8);
        leaves[TURN_TRACKER_IDX] = hash_leaf(PlayerRole::O as u8);
        let root_after_move0 = compute_root_from_leaves(&leaves);

        let m1 = PlayerMove::Play {
            pubkey: p2.pk,
            coords: (1, 1),
        };
        legit[1].signature = attacker
            .sk
            .sign(&format_auth_message(&m1, root_after_move0))
            .to_vec();

        let req = BatchRequest {
            game_id: gid,
            moves: legit,
        };
        let res = client
            .post(format!("{url}/game/play_batch"))
            .json(&req)
            .send()
            .await
            .unwrap();
        let status = res.status();
        println!(
            "👿 [MALICIOUS BATCH] {} injected move 1. Server responded: {status}",
            attacker.name
        );
        assert!(
            status.is_client_error(),
            "Malicious batch should have been rejected!"
        );
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let base_url = "http://127.0.0.1:3000";

    let alice = Arc::new(TestPlayer::new("Alice"));
    let bob = Arc::new(TestPlayer::new("Bob"));
    let charlie = Arc::new(TestPlayer::new("Charlie"));

    // ── Individual-move games ──────────────────────────────────────────────────
    println!("🎭 Starting Parallel Multi-Game Stress Test...");

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();

    let mut handles = vec![
        spawn_game(
            client.clone(),
            base_url,
            alice.clone(),
            bob.clone(),
            vec![
                (0, 0),
                (0, 1),
                (0, 2),
                (1, 1),
                (1, 0),
                (1, 2),
                (2, 1),
                (2, 0),
                (2, 2),
            ],
            "GAME 1 (TIE)",
            Some(tx1),
        ),
        spawn_game(
            client.clone(),
            base_url,
            bob.clone(),
            charlie.clone(),
            vec![(0, 0), (1, 0), (0, 1), (1, 1), (0, 2)],
            "GAME 2 (BOB WINS)",
            Some(tx2),
        ),
        spawn_game(
            client.clone(),
            base_url,
            charlie.clone(),
            alice.clone(),
            vec![(0, 0), (1, 0), (0, 1), (1, 1), (0, 2)],
            "GAME 3 (CHARLIE WINS)",
            None,
        ),
        spawn_game(
            client.clone(),
            base_url,
            bob.clone(),
            alice.clone(),
            vec![(1, 1), (0, 0), (0, 1), (1, 0), (2, 2), (2, 0)],
            "GAME 4 (ALICE WINS)",
            None,
        ),
    ];

    // Malicious individual-move attempts
    let charlie_clone = charlie.clone();
    let bob_pk = bob.pk;
    let client_clone = client.clone();
    let malicious_handle = tokio::spawn(async move {
        if let Ok(target_gid) = rx1.await {
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

    println!("\n🗂️  Starting Batch Move Tests...");

    let batch_handles = vec![
        spawn_batch_game(
            client.clone(),
            base_url,
            alice.clone(),
            bob.clone(),
            vec![(0, 0), (0, 1), (1, 0), (1, 1), (2, 0)],
            "BATCH 1 (ALICE WINS)",
        ),
        spawn_batch_game(
            client.clone(),
            base_url,
            bob.clone(),
            charlie.clone(),
            vec![
                (0, 0),
                (0, 1),
                (0, 2),
                (1, 1),
                (1, 0),
                (1, 2),
                (2, 1),
                (2, 0),
                (2, 2),
            ],
            "BATCH 2 (DRAW)",
        ),
        spawn_batch_game(
            client.clone(),
            base_url,
            charlie.clone(),
            alice.clone(),
            vec![(1, 1), (0, 0), (2, 2)],
            "BATCH 3 (PARTIAL)",
        ),
        spawn_malicious_batch(
            client.clone(),
            base_url,
            alice.clone(),
            bob.clone(),
            charlie.clone(),
        ),
    ];

    println!("⏳ Awaiting batch results...");
    for handle in batch_handles {
        handle.await.unwrap();
    }

    println!("\n🏁 All scenarios completed!");
    Ok(())
}
