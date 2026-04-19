use ed25519_dalek::Signature;
use ttt_core::{
    logic::{Player, PlayerMove},
    merkle::Hash,
};

// Helper function to parse a provided byte slice into a ed25519_dalek signature
fn parse_signature(sig_vec: &[u8]) -> Result<Signature, String> {
    let bytes: [u8; 64] = sig_vec
        .try_into()
        .map_err(|_| "Signature must be exactly 64 bytes".to_string())?;
    Ok(Signature::from_bytes(&bytes))
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct CreateRequest {
    pub pubkey_x: Player,
    pub pubkey_y: Player,
    pub signature: Vec<u8>,
    pub nonce: u64,
}

impl CreateRequest {
    pub fn dalek_signature(&self) -> Result<Signature, String> {
        parse_signature(&self.signature)
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct CreateResponse {
    pub game_id: u128,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct PlayRequest {
    pub game_id: u128,
    pub x: usize,
    pub y: usize,
    pub pubkey: Player,
    pub signature: Vec<u8>,
}

impl PlayRequest {
    pub fn dalek_signature(&self) -> Result<Signature, String> {
        parse_signature(&self.signature)
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct PlayResponse {
    pub new_root: Hash,
    pub winner: Option<Player>,
}

impl From<PlayRequest> for PlayerMove {
    fn from(req: PlayRequest) -> Self {
        Self::Play {
            pubkey: req.pubkey,
            coords: (req.x, req.y),
        }
    }
}

impl From<CreateRequest> for PlayerMove {
    fn from(req: CreateRequest) -> Self {
        Self::CreateGame {
            pubkey_x: req.pubkey_x,
            pubkey_y: req.pubkey_y,
        }
    }
}
