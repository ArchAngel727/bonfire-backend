use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ChannelKind {
    Dm,
    Text,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Channel {
    pub channel_id: Uuid,
    pub kind: ChannelKind,
    pub name: Option<String>,
    pub dm_user_low: Option<Uuid>,
    pub dm_user_low_username: Option<String>,
    pub dm_user_high: Option<Uuid>,
    pub dm_user_high_username: Option<String>,
    pub created_at: DateTime<Utc>,
}
