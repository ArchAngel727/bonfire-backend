use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto_manager::CryptoManager;

#[derive(Serialize, Deserialize, Debug)]
pub struct Cookie {
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    session_id: [u8; 16],
    user_id: [u8; 16],
}

impl Cookie {
    pub fn new(user_id: [u8; 16]) -> Self {
        Self {
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            session_id: Uuid::new_v4().into_bytes(),
            user_id,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedCookie {
    pub cookie: Cookie,
    pub signiture: String,
}

impl SignedCookie {
    pub fn new(cookie: Cookie) -> Option<Self> {
        CryptoManager::sign_cookie(&cookie).map(|signiture| Self { cookie, signiture })
    }
}
