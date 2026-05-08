use chrono::Utc;
use serde::{Deserialize, Serialize};
use socketioxide::extract::{AckSender, Data, SocketRef, State};
use sqlx::{Pool, Sqlite};
use uuid::Uuid;

use crate::{cookie::Cookie, user::AuthedUser};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "status")]
pub enum AuthResponse {
    Success,
    Failed,
}

pub async fn auth(socket: SocketRef) {
    socket.on(
        "request_new_session",
        async |Data::<Cookie>(data),
               ack: AckSender,
               socket: SocketRef,
               State(db): State<Pool<Sqlite>>| {
            let session_id_bytes = &data.session_id[..];
            let now = Utc::now();
            let session = match sqlx::query!(
                r#"SELECT user_id as "user_id!: Uuid"
                FROM sessions
                WHERE session_id = ?1 AND expires_at > ?2"#,
                session_id_bytes,
                now,
            )
            .fetch_optional(&db)
            .await
            {
                Ok(Some(row)) => row,
                Ok(None) => {
                    // no session or expired
                    ack.send(&AuthResponse::Failed).ok();
                    return;
                }
                Err(e) => {
                    eprintln!("session lookup failed: {e:?}");
                    ack.send(&AuthResponse::Failed).ok();
                    return;
                }
            };

            socket.extensions.insert(AuthedUser {
                user_id: session.user_id,
            });

            let new_expires_at = now + chrono::Duration::days(7);
            let _ = sqlx::query!(
                "UPDATE sessions SET expires_at = ?1 WHERE session_id = ?2",
                new_expires_at,
                session_id_bytes,
            )
            .execute(&db)
            .await;

            ack.send(&AuthResponse::Success).ok();
        },
    );
}
