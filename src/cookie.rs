use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Cookie {
    pub session_id: [u8; 16],
    pub signature: [u8; 32],
}

impl Cookie {
    pub fn new(session_id: [u8; 16], signature: [u8; 32]) -> Self {
        Self {
            session_id,
            signature,
        }
    }
}
