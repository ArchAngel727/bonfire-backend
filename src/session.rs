use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Session {
    pub user_id: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl Session {
    pub fn new(user_id: Vec<u8>) -> Self {
        Self {
            user_id,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
        }
    }
}
