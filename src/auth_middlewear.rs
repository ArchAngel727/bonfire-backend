use chrono::{DateTime, Utc};
use socketioxide::extract::{SocketRef, State, TryData};
use sqlx::{Pool, Sqlite};
use thiserror::Error;
use tracing::debug;
use uuid::Uuid;

use crate::{cookie::Cookie, crypto_manager::CryptoManager, session::Session, user::UserID};

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("AUTH_REQUIRED")]
    Missing,
    #[error("SESSION_EXPIRED")]
    Expired,
    #[error("SESSION_INVALID")]
    Invalid,
    #[error("INTERNAL_ERROR {0}")]
    Internal(#[from] sqlx::Error),
}

pub async fn auth_middlewear(
    socket: SocketRef,
    TryData(cookie): TryData<Cookie>,
    State(cm): State<CryptoManager>,
    State(db): State<Pool<Sqlite>>,
) -> Result<(), AuthError> {
    let cookie = cookie
        .inspect_err(|e| debug!("{:?}", e))
        .map_err(|_| AuthError::Missing)?;

    if !cm.verify(&cookie.session_id, &cookie.signature) {
        return Err(AuthError::Invalid);
    }

    let slice = &cookie.session_id[..];
    let session = sqlx::query_as!(
        Session,
        r#"SELECT
                user_id as "user_id: Uuid",
                created_at as "created_at: DateTime<Utc>",
                expires_at as "expires_at: DateTime<Utc>"
                FROM sessions WHERE
                session_id = ?1"#,
        slice
    )
    .fetch_optional(&db)
    .await?
    .ok_or(AuthError::Invalid)?;

    if Utc::now() > session.expires_at {
        return Err(AuthError::Expired);
    }

    socket.extensions.insert(UserID(session.user_id));

    Ok(())
}
