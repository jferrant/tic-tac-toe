use ttt_core::{
    logic::{Player, PlayerMove},
    merkle::Hash,
};

#[derive(serde::Deserialize, serde::Serialize)]
pub struct CreateRequest {
    pub pubkey_x: Player,
    pub pubkey_y: Player,
    pub signature: Vec<u8>,
    pub nonce: u128,
}

impl CreateRequest {
    /// Helper to get the raw [u8; 64] for the Witness
    pub fn signature_bytes(&self) -> Result<[u8; 64], String> {
        self.signature
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid signature length".to_string())
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
    /// Helper to get the raw [u8; 64] for the Witness
    pub fn signature_bytes(&self) -> Result<[u8; 64], String> {
        self.signature
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid signature length".to_string())
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
            nonce: req.nonce,
        }
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct BatchMoveRequest {
    pub x: usize,
    pub y: usize,
    pub signature: Vec<u8>,
}

impl BatchMoveRequest {
    pub fn signature_bytes(&self) -> Result<[u8; 64], String> {
        self.signature
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid signature length".to_string())
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct BatchRequest {
    pub game_id: u128,
    pub moves: Vec<BatchMoveRequest>,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct BatchResponse {
    pub new_root: Hash,
    pub winner: Option<Player>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_request_to_player_move() {
        let req = CreateRequest {
            pubkey_x: [1u8; 32],
            pubkey_y: [2u8; 32],
            signature: vec![0u8; 64],
            nonce: 42,
        };

        let m: PlayerMove = req.into();

        if let PlayerMove::CreateGame {
            pubkey_x,
            pubkey_y,
            nonce,
        } = m
        {
            assert_eq!(pubkey_x, [1u8; 32]);
            assert_eq!(pubkey_y, [2u8; 32]);
            assert_eq!(nonce, 42);
        } else {
            panic!("Wrong variant converted");
        }
    }

    #[test]
    fn play_request_to_player_move() {
        let req = PlayRequest {
            game_id: 100,
            x: 1,
            y: 2,
            pubkey: [3u8; 32],
            signature: vec![0u8; 64],
        };

        let m: PlayerMove = req.into();

        if let PlayerMove::Play { pubkey, coords } = m {
            assert_eq!(pubkey, [3u8; 32]);
            assert_eq!(coords, (1, 2));
        } else {
            panic!("Wrong variant converted");
        }
    }

    #[test]
    fn signature_bytes_validation() {
        let mut req = PlayRequest {
            game_id: 1,
            x: 0,
            y: 0,
            pubkey: [0u8; 32],
            signature: vec![0u8; 64], // Correct length
        };

        // Success case
        assert!(req.signature_bytes().is_ok());

        // Failure case: too short
        req.signature = vec![0u8; 63];
        assert_eq!(
            req.signature_bytes().unwrap_err(),
            "Invalid signature length"
        );

        // Failure case: too long
        req.signature = vec![0u8; 65];
        assert_eq!(
            req.signature_bytes().unwrap_err(),
            "Invalid signature length"
        );
    }
}
