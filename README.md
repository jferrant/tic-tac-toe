# ZK-Verifiable Tic-Tac-Toe

A cryptographically-authenticated Tic-Tac-Toe server built in Rust, designed so that every game can be proven in a zkVM. The core State Transition Function (STF) is a pure function — no I/O, no global state — that takes a prior Merkle root, a player move, and a witness, and returns a new Merkle root plus an optional winner.

**Stack:** Rust · Tokio · Axum · Ed25519-Dalek · SHA-256 Merkle tree · Serde

---

## Project Structure

```
ttt-core/   Pure game logic (STF, Merkle tree, witness types)
server/     Axum HTTP server + stateful coordinator
  src/bin/dummy.rs   Parallel stress-test + batch harness
```

`ttt-core` has no server dependencies and can be dropped directly into a zkVM guest program.

---

## Merkle Tree Design

Each game state is committed to a 16-leaf SHA-256 Merkle tree:

| Index | Contents |
| :---: | :--- |
| 0–8 | Board cells (`Empty=0`, `X=1`, `O=2`) — one byte per cell |
| 9 | Player X public key — `hash_leaf(sha256(pk_x))` |
| 10 | Player O public key — `hash_leaf(sha256(pk_o))` |
| 11 | Turn tracker — `hash_leaf(1)` for X's turn, `hash_leaf(2)` for O's |
| 12–15 | Padding (`NULL_HASH`) |

The Merkle root is the single compact commitment to the entire game state. Two states are equal if and only if their roots match.

---

## State Transition Function

```rust
pub fn stf(
    prior_root: Hash,
    player_move: &PlayerMove,
    witness: &Witness,
) -> Result<(Hash, Option<Winner>), StfError>
```

The STF is intentionally pure: given the same inputs it always produces the same outputs, with no side effects. This is the property that makes it provable in a zkVM as the prover just runs `stf` inside the guest and the verifier checks the proof.

### What the STF verifies for a `Play` move

1. **Signature**: the player signed `("PLAY:", pubkey, coords, prior_root)` with their private key. Binding the signature to `prior_root` prevents replay attacks across different game states.
2. **Merkle proof**: reconstruct all 16 leaves from the compact witness and assert `compute_root(leaves) == prior_root`. A wrong pubkey, wrong turn, or tampered board all produce a different root and fail here.
3. **Occupancy**: the target cell is `Empty`.
4. **Win detection**: after applying the move, check all 8 win conditions against the updated leaves.

Identity and turn enforcement are folded into step 2: there is no separate `if pubkey != registered_player` check. The wrong pubkey simply produces the wrong root.

---

## Witness Minimization

The naive witness (all 16 × 32-byte leaves) is **576 bytes** per move. The optimized witness is **106 bytes**:

| Field | Size | Reason |
| :--- | ---: | :--- |
| `board: [Cell; 9]` | 9 B | Raw `u8` values, not 32-byte hashes |
| `turn: PlayerRole` | 1 B | Raw `u8`, not a 32-byte hash |
| `other_player_pubkey` | 32 B | Current player's key comes from the move itself |
| `signature` | 64 B | Ed25519 |
| **Total** | **106 B** | vs. 576 B naive |

The savings come from three insights:
- Store raw `Cell` values (1 byte) and re-hash them inside the STF rather than transmitting pre-hashed leaves (32 bytes each).
- The current player's pubkey is already in the `PlayerMove` so we don't need to repeat it in the witness.
- Padding leaves 12–15 are always `NULL_HASH` by definition, so they're deterministic and can be omitted entirely.

---

## Batch STF

```rust
pub fn batch_stf(
    prior_root: Hash,
    initial_board: [Cell; 9],
    initial_turn: PlayerRole,
    pk_x: Player,
    pk_o: Player,
    moves: &[BatchMove],          // BatchMove = { coords, signature } = 72 bytes
) -> Result<(Hash, [Cell; 9], PlayerRole, Option<Winner>), StfError>
```

Processing multiple moves in a single ZK proof is more efficient than chaining individual proofs:

| Approach | Bytes per move |
| :--- | ---: |
| Individual `stf` calls | 106 B × N |
| `batch_stf` (initial state) | 74 B once |
| `batch_stf` (subsequent moves) | **72 B each** |

After verifying the initial board/turn/pubkeys against `prior_root` once, subsequent moves only need `coords` (8 bytes) and a `signature` (64 bytes) because the board state is threaded through internally.

Each move in a batch still signs against the root *before that move is applied*, so the signature chain is identical in structure to the individual STF. The batch just avoids re-transmitting state the verifier already holds.

---

## HTTP API

| Method | Path | Description |
| :--- | :--- | :--- |
| `POST` | `/game/create` | Initialize a new game; p1 signs the creation |
| `POST` | `/game/play` | Submit a single move |
| `POST` | `/game/play_batch` | Submit multiple moves in one request |

### Create a game

```json
POST /game/create
{
  "pubkey_x": "<32-byte hex>",
  "pubkey_y": "<32-byte hex>",
  "nonce": 42,
  "signature": "<64-byte sig over CREATE_GAME message>"
}
```

### Play a move

```json
POST /game/play
{
  "game_id": 123,
  "x": 0, "y": 0,
  "pubkey": "<32-byte hex>",
  "signature": "<64-byte sig over PLAY message + prior_root>"
}
```

### Play a batch

```json
POST /game/play_batch
{
  "game_id": 123,
  "moves": [
    { "x": 0, "y": 0, "signature": "..." },
    { "x": 1, "y": 1, "signature": "..." }
  ]
}
```

Each signature in the batch must be computed against the root produced by all prior moves in the same batch: see `presign_batch` in `dummy.rs` for the pattern.

---

## Running

```bash
# Start the server (default: 127.0.0.1:3000)
cargo run -p server

# Run the parallel stress test + batch harness
cargo run -p server --bin dummy
```

---

## Adversarial Test Vectors

The `dummy` binary validates the following attack scenarios alongside normal play:

| Scenario | Attack | Expected |
| :--- | :--- | :--- |
| **Identity hijacking** | Third party submits a move signed with their own key into another player's game | `400` — root mismatch |
| **Out-of-turn execution** | Legitimate player submits a move when it is not their turn | `400` — root mismatch (turn tracker leaf differs) |
| **Batch signature injection** | Attacker replaces one signature in a batch with their own | `400` — `InvalidSignature` |

All three fail at the Merkle root check or signature verification (there is no separate authorization layer to bypass).

---

## Concurrency Model

The server stores game state in a `RwLock<HashMap<u128, StoredGame>>`. Reads (witness construction, state lookup) take a shared lock; writes (create, update) take an exclusive lock. For production scale, a sharded structure like `DashMap` or an actor-per-game model would eliminate contention between independent games.
Game IDs are derived as `sha256(pk_x || pk_o || nonce)[..16]`, which makes them deterministic for a given player pair and nonce while being collision-resistant in practice.
