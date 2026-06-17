use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use socketioxide::extract::{AckSender, Data, SocketRef, State};
use sqlx::{Pool, Sqlite};
use thiserror::Error;
use tracing::{debug, error};
use uuid::Uuid;

use crate::{
    channel::{Channel, ChannelKind},
    message_crypto::MessageCrypto,
    permissions::{AdminId, can_create_text_channel, is_mod},
    user::UserID,
};

const TEXT_ROOM: &str = "text";

fn user_room(user_id: &Uuid) -> String {
    format!("user:{}", user_id)
}

enum ChannelAccess {
    Text,
    Dm { low: Uuid, high: Uuid },
}

impl ChannelAccess {
    fn kind(&self) -> ChannelKind {
        match self {
            ChannelAccess::Text => ChannelKind::Text,
            ChannelAccess::Dm { .. } => ChannelKind::Dm,
        }
    }

    fn rooms(&self) -> Vec<String> {
        match self {
            ChannelAccess::Text => vec![TEXT_ROOM.to_string()],
            ChannelAccess::Dm { low, high } => vec![user_room(low), user_room(high)],
        }
    }
}

#[derive(Debug, Error)]
pub enum ChannelError {
    #[error("UNAUTHENTICATED")]
    Unauthenticated,
    #[error("BAD_REQUEST: {0}")]
    BadRequest(&'static str),
    #[error("FORBIDDEN")]
    Forbidden,
    #[error("NOT_FOUND")]
    NotFound,
    #[error("INTERNAL")]
    Internal,
}

impl From<sqlx::Error> for ChannelError {
    fn from(e: sqlx::Error) -> Self {
        error!("channel db error: {e:?}");
        ChannelError::Internal
    }
}

fn current_user(socket: &SocketRef) -> Result<Uuid, ChannelError> {
    socket
        .extensions
        .get::<UserID>()
        .map(|u| u.0)
        .ok_or(ChannelError::Unauthenticated)
}

async fn access_channel(
    me: &Uuid,
    channel_id: &Uuid,
    db: &Pool<Sqlite>,
) -> Result<ChannelAccess, ChannelError> {
    let row = sqlx::query!(
        r#"SELECT kind as "kind!: ChannelKind",
                  dm_user_low as "dm_user_low: Uuid",
                  dm_user_high as "dm_user_high: Uuid"
           FROM channels WHERE channel_id = ?1"#,
        channel_id
    )
    .fetch_optional(db)
    .await?
    .ok_or(ChannelError::NotFound)?;

    match row.kind {
        ChannelKind::Text => Ok(ChannelAccess::Text),
        ChannelKind::Dm => match (row.dm_user_low, row.dm_user_high) {
            (Some(low), Some(high)) if &low == me || &high == me => {
                Ok(ChannelAccess::Dm { low, high })
            }
            (Some(_), Some(_)) => Err(ChannelError::Forbidden),
            _ => {
                error!("dm channel {channel_id} missing participants");
                Err(ChannelError::Internal)
            }
        },
    }
}

async fn username_of(user_id: &Uuid, db: &Pool<Sqlite>) -> Result<String, sqlx::Error> {
    sqlx::query_scalar!("SELECT username FROM users WHERE user_id = ?1", user_id)
        .fetch_one(db)
        .await
}

/// Hydrate a channel row into the full Channel struct (with DM usernames joined).
async fn fetch_channel(channel_id: &Uuid, db: &Pool<Sqlite>) -> Result<Channel, ChannelError> {
    let row = sqlx::query!(
        r#"SELECT
            c.channel_id as "channel_id!: Uuid",
            c.kind as "kind!: ChannelKind",
            c.name,
            c.dm_user_low as "dm_user_low: Uuid",
            ulow.username as "dm_user_low_username: String",
            c.dm_user_high as "dm_user_high: Uuid",
            uhigh.username as "dm_user_high_username: String",
            c.created_at as "created_at!: DateTime<Utc>"
           FROM channels c
           LEFT JOIN users ulow ON ulow.user_id = c.dm_user_low
           LEFT JOIN users uhigh ON uhigh.user_id = c.dm_user_high
           WHERE c.channel_id = ?1"#,
        channel_id
    )
    .fetch_optional(db)
    .await?
    .ok_or(ChannelError::NotFound)?;

    Ok(Channel {
        channel_id: row.channel_id,
        kind: row.kind,
        name: row.name,
        dm_user_low: row.dm_user_low,
        dm_user_low_username: Some(row.dm_user_low_username),
        dm_user_high: row.dm_user_high,
        dm_user_high_username: Some(row.dm_user_high_username),
        created_at: row.created_at,
    })
}

#[derive(Deserialize, Debug)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ChannelCreateRequest {
    Dm { other: Uuid },
    Text { name: String },
}

#[derive(Serialize, Debug)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum ChannelCreateResponse {
    Ok { channel: Channel },
    Error { reason: String },
}

async fn handle_channel_create(
    me: Uuid,
    req: ChannelCreateRequest,
    admin: &AdminId,
    db: &Pool<Sqlite>,
) -> Result<Channel, ChannelError> {
    let now = Utc::now();
    let channel_id = Uuid::new_v4();
    let kind_dm = "dm";
    let kind_text = "text";

    match req {
        ChannelCreateRequest::Dm { other } => {
            if other == me {
                return Err(ChannelError::BadRequest("cannot DM yourself"));
            }
            let (low, high) = if me < other { (me, other) } else { (other, me) };

            let insert = sqlx::query!(
                r#"INSERT INTO channels
                   (channel_id, kind, name, dm_user_low, dm_user_high, created_at)
                   VALUES (?1, ?2, NULL, ?3, ?4, ?5)"#,
                channel_id,
                kind_dm,
                low,
                high,
                now
            )
            .execute(db)
            .await;

            match insert {
                Ok(_) => fetch_channel(&channel_id, db).await,
                Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                    let existing_id = sqlx::query_scalar!(
                        r#"SELECT channel_id as "channel_id!: Uuid"
                           FROM channels
                           WHERE kind = 'dm' AND dm_user_low = ?1 AND dm_user_high = ?2"#,
                        low,
                        high
                    )
                    .fetch_one(db)
                    .await?;
                    fetch_channel(&existing_id, db).await
                }
                Err(e) => Err(e.into()),
            }
        }
        ChannelCreateRequest::Text { name } => {
            if !can_create_text_channel(&me, admin, db).await? {
                return Err(ChannelError::Forbidden);
            }
            let trimmed = name.trim();
            if trimmed.is_empty() || trimmed.len() > 64 {
                return Err(ChannelError::BadRequest("name must be 1-64 chars"));
            }
            let result = sqlx::query!(
                r#"INSERT INTO channels
                   (channel_id, kind, name, dm_user_low, dm_user_high, created_at)
                   VALUES (?1, ?2, ?3, NULL, NULL, ?4)"#,
                channel_id,
                kind_text,
                trimmed,
                now
            )
            .execute(db)
            .await;

            match result {
                Ok(_) => fetch_channel(&channel_id, db).await,
                Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                    Err(ChannelError::BadRequest("channel name already taken"))
                }
                Err(e) => Err(e.into()),
            }
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct ChannelSendRequest {
    pub channel_id: Uuid,
    pub content: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChannelMessage {
    pub message_id: Uuid,
    pub channel_id: Uuid,
    pub author_id: Uuid,
    pub author_username: String,
    pub seq: i64,
    pub content: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize, Debug)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum ChannelSendResponse {
    Ok { message: ChannelMessage },
    Error { reason: String },
}

async fn handle_channel_send(
    me: Uuid,
    req: ChannelSendRequest,
    crypto: &MessageCrypto,
    db: &Pool<Sqlite>,
) -> Result<(ChannelMessage, ChannelAccess), ChannelError> {
    let access = access_channel(&me, &req.channel_id, db).await?;

    let message_id = Uuid::new_v4();
    let now = Utc::now();

    // Text channels: encrypt before storing. DMs: store the bytes the client
    // sent untouched (in phase 4 these will already be Olm ciphertext).
    let stored_content: Vec<u8> = match access {
        ChannelAccess::Text => crypto.encrypt(&req.content).map_err(|e| {
            error!("encrypt failed: {e}");
            ChannelError::Internal
        })?,
        ChannelAccess::Dm { .. } => req.content.clone(),
    };

    let mut tx = db.begin().await?;
    let next_seq = sqlx::query_scalar!(
        r#"SELECT COALESCE(MAX(seq), 0) + 1 as "next!: i64"
           FROM messages WHERE channel_id = ?1"#,
        req.channel_id
    )
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query!(
        r#"INSERT INTO messages
           (message_id, channel_id, author_id, seq, content, created_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
        message_id,
        req.channel_id,
        me,
        next_seq,
        stored_content,
        now
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let author_username = username_of(&me, db).await?;

    // Broadcast and ack carry the plaintext (or, for DMs in phase 4, the
    // client's Olm ciphertext as-is). Only the row in the DB is encrypted.
    Ok((
        ChannelMessage {
            message_id,
            channel_id: req.channel_id,
            author_id: me,
            author_username,
            seq: next_seq,
            content: req.content,
            created_at: now,
        },
        access,
    ))
}

#[derive(Deserialize, Debug)]
pub struct ChannelSyncRequest {
    pub channel_id: Uuid,
    pub since_seq: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Serialize, Debug)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum ChannelSyncResponse {
    Ok { messages: Vec<ChannelMessage> },
    Error { reason: String },
}

async fn handle_channel_sync(
    me: Uuid,
    req: ChannelSyncRequest,
    crypto: &MessageCrypto,
    db: &Pool<Sqlite>,
) -> Result<Vec<ChannelMessage>, ChannelError> {
    let access = access_channel(&me, &req.channel_id, db).await?;
    let limit = req.limit.unwrap_or(50).clamp(1, 200);

    let mut messages: Vec<ChannelMessage> = match req.since_seq {
        Some(since) => sqlx::query!(
            r#"SELECT
                m.message_id as "message_id!: Uuid",
                m.channel_id as "channel_id!: Uuid",
                m.author_id as "author_id!: Uuid",
                u.username as "author_username!: String",
                m.seq as "seq!: i64",
                m.content as "content!: Vec<u8>",
                m.created_at as "created_at!: DateTime<Utc>"
               FROM messages m
               JOIN users u ON u.user_id = m.author_id
               WHERE m.channel_id = ?1 AND m.seq > ?2
               ORDER BY m.seq ASC
               LIMIT ?3"#,
            req.channel_id,
            since,
            limit
        )
        .fetch_all(db)
        .await?
        .into_iter()
        .map(|r| ChannelMessage {
            message_id: r.message_id,
            channel_id: r.channel_id,
            author_id: r.author_id,
            author_username: r.author_username,
            seq: r.seq,
            content: r.content,
            created_at: r.created_at,
        })
        .collect(),
        None => {
            let mut rows: Vec<ChannelMessage> = sqlx::query!(
                r#"SELECT
                    m.message_id as "message_id!: Uuid",
                    m.channel_id as "channel_id!: Uuid",
                    m.author_id as "author_id!: Uuid",
                    u.username as "author_username!: String",
                    m.seq as "seq!: i64",
                    m.content as "content!: Vec<u8>",
                    m.created_at as "created_at!: DateTime<Utc>"
                   FROM messages m
                   JOIN users u ON u.user_id = m.author_id
                   WHERE m.channel_id = ?1
                   ORDER BY m.seq DESC
                   LIMIT ?2"#,
                req.channel_id,
                limit
            )
            .fetch_all(db)
            .await?
            .into_iter()
            .map(|r| ChannelMessage {
                message_id: r.message_id,
                channel_id: r.channel_id,
                author_id: r.author_id,
                author_username: r.author_username,
                seq: r.seq,
                content: r.content,
                created_at: r.created_at,
            })
            .collect();
            rows.reverse();
            rows
        }
    };

    // Decrypt text channel content; DM content is returned as stored.
    if matches!(access, ChannelAccess::Text) {
        for msg in &mut messages {
            match crypto.decrypt(&msg.content) {
                Ok(plain) => msg.content = plain,
                Err(e) => {
                    error!(
                        "decrypt failed for message {}: {e}; returning placeholder",
                        msg.message_id
                    );
                    msg.content = b"[decryption failed]".to_vec();
                }
            }
        }
    }

    Ok(messages)
}

#[derive(Serialize, Debug)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum ChannelListResponse {
    Ok { channels: Vec<Channel> },
    Error { reason: String },
}

async fn handle_channel_list(me: Uuid, db: &Pool<Sqlite>) -> Result<Vec<Channel>, ChannelError> {
    let rows = sqlx::query!(
        r#"SELECT
            c.channel_id as "channel_id!: Uuid",
            c.kind as "kind!: ChannelKind",
            c.name,
            c.dm_user_low as "dm_user_low: Uuid",
            ulow.username as "dm_user_low_username: String",
            c.dm_user_high as "dm_user_high: Uuid",
            uhigh.username as "dm_user_high_username: String",
            c.created_at as "created_at!: DateTime<Utc>"
           FROM channels c
           LEFT JOIN users ulow ON ulow.user_id = c.dm_user_low
           LEFT JOIN users uhigh ON uhigh.user_id = c.dm_user_high
           WHERE c.kind = 'text'
              OR (c.kind = 'dm' AND (c.dm_user_low = ?1 OR c.dm_user_high = ?1))
           ORDER BY c.created_at DESC"#,
        me
    )
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| Channel {
            channel_id: r.channel_id,
            kind: r.kind,
            name: r.name,
            dm_user_low: r.dm_user_low,
            dm_user_low_username: r.dm_user_low_username,
            dm_user_high: r.dm_user_high,
            dm_user_high_username: r.dm_user_high_username,
            created_at: r.created_at,
        })
        .collect())
}

#[derive(Deserialize, Debug)]
pub struct ChannelDeleteMessageRequest {
    pub channel_id: Uuid,
    pub message_id: Uuid,
}

#[derive(Serialize, Debug)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum ChannelDeleteMessageResponse {
    Ok,
    Error { reason: String },
}

async fn handle_channel_delete_message(
    me: Uuid,
    req: &ChannelDeleteMessageRequest,
    admin: &AdminId,
    db: &Pool<Sqlite>,
) -> Result<ChannelAccess, ChannelError> {
    let access = access_channel(&me, &req.channel_id, db).await?;

    let msg = sqlx::query!(
        r#"SELECT author_id as "author_id!: Uuid"
           FROM messages WHERE message_id = ?1 AND channel_id = ?2"#,
        req.message_id,
        req.channel_id
    )
    .fetch_optional(db)
    .await?
    .ok_or(ChannelError::NotFound)?;

    let allowed = msg.author_id == me
        || (access.kind() == ChannelKind::Text && (admin.is(&me) || is_mod(&me, db).await?));

    if !allowed {
        return Err(ChannelError::Forbidden);
    }

    sqlx::query!("DELETE FROM messages WHERE message_id = ?1", req.message_id)
        .execute(db)
        .await?;

    Ok(access)
}

#[derive(Deserialize, Debug)]
pub struct ChannelRenameRequest {
    pub channel_id: Uuid,
    pub name: String,
}

#[derive(Serialize, Debug)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum ChannelRenameResponse {
    Ok { channel: Channel },
    Error { reason: String },
}

async fn handle_channel_rename(
    me: Uuid,
    req: &ChannelRenameRequest,
    admin: &AdminId,
    db: &Pool<Sqlite>,
) -> Result<Channel, ChannelError> {
    match access_channel(&me, &req.channel_id, db).await? {
        ChannelAccess::Text => {}
        ChannelAccess::Dm { .. } => return Err(ChannelError::BadRequest("cannot rename a DM")),
    }

    if !(admin.is(&me) || is_mod(&me, db).await?) {
        return Err(ChannelError::Forbidden);
    }

    let trimmed = req.name.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return Err(ChannelError::BadRequest("name must be 1-64 chars"));
    }

    let result = sqlx::query!(
        "UPDATE channels SET name = ?1 WHERE channel_id = ?2 AND kind = 'text'",
        trimmed,
        req.channel_id
    )
    .execute(db)
    .await;

    match result {
        Ok(r) if r.rows_affected() == 1 => {}
        Ok(_) => return Err(ChannelError::NotFound),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(ChannelError::BadRequest("channel name already taken"));
        }
        Err(e) => return Err(e.into()),
    }

    fetch_channel(&req.channel_id, db).await
}

#[derive(Deserialize, Debug)]
pub struct ChannelDeleteRequest {
    pub channel_id: Uuid,
}

#[derive(Serialize, Debug)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum ChannelDeleteResponse {
    Ok,
    Error { reason: String },
}

async fn handle_channel_delete(
    me: Uuid,
    req: &ChannelDeleteRequest,
    admin: &AdminId,
    db: &Pool<Sqlite>,
) -> Result<(), ChannelError> {
    match access_channel(&me, &req.channel_id, db).await? {
        ChannelAccess::Text => {}
        ChannelAccess::Dm { .. } => return Err(ChannelError::BadRequest("cannot delete a DM")),
    }

    if !(admin.is(&me) || is_mod(&me, db).await?) {
        return Err(ChannelError::Forbidden);
    }

    let r = sqlx::query!(
        "DELETE FROM channels WHERE channel_id = ?1 AND kind = 'text'",
        req.channel_id
    )
    .execute(db)
    .await?;

    if r.rows_affected() == 1 {
        Ok(())
    } else {
        Err(ChannelError::NotFound)
    }
}

// ───── lookup_user (any authenticated user) ─────

#[derive(Deserialize, Debug)]
pub struct LookupUserRequest {
    pub username: String,
}

#[derive(Serialize, Debug)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum LookupUserResponse {
    Ok { user_id: Uuid, username: String },
    Error { reason: String },
}

async fn handle_lookup_user(
    req: LookupUserRequest,
    db: &Pool<Sqlite>,
) -> Result<(Uuid, String), ChannelError> {
    let username = req.username.trim();
    if username.is_empty() {
        return Err(ChannelError::BadRequest("username is required"));
    }
    let row = sqlx::query!(
        r#"SELECT user_id as "user_id!: Uuid", username FROM users WHERE username = ?1"#,
        username
    )
    .fetch_optional(db)
    .await?
    .ok_or(ChannelError::NotFound)?;
    Ok((row.user_id, row.username))
}

pub async fn channel(socket: SocketRef) {
    if let Ok(me) = current_user(&socket) {
        socket.join(TEXT_ROOM.to_string());
        socket.join(user_room(&me));
    } else {
        debug!("connect without UserID (middleware misconfigured?)");
    }

    socket.on(
        "channel_create",
        async |socket: SocketRef,
               ack: AckSender,
               Data::<ChannelCreateRequest>(data),
               State(db): State<Pool<Sqlite>>,
               State(admin): State<AdminId>| {
            let me = match current_user(&socket) {
                Ok(u) => u,
                Err(e) => {
                    ack.send(&ChannelCreateResponse::Error {
                        reason: e.to_string(),
                    })
                    .ok();
                    return;
                }
            };
            match handle_channel_create(me, data, &admin, &db).await {
                Ok(channel) => {
                    match channel.kind {
                        ChannelKind::Text => {
                            let _ = socket.to(TEXT_ROOM).emit("channel_created", &channel).await;
                        }
                        ChannelKind::Dm => {
                            let other = if channel.dm_user_low == Some(me) {
                                channel.dm_user_high
                            } else {
                                channel.dm_user_low
                            };
                            if let Some(other) = other {
                                let _ = socket
                                    .to(user_room(&other))
                                    .emit("channel_created", &channel)
                                    .await;
                            }
                        }
                    }
                    ack.send(&ChannelCreateResponse::Ok { channel }).ok();
                }
                Err(e) => {
                    ack.send(&ChannelCreateResponse::Error {
                        reason: e.to_string(),
                    })
                    .ok();
                }
            }
        },
    );

    socket.on(
        "channel_send",
        async |socket: SocketRef,
               ack: AckSender,
               Data::<ChannelSendRequest>(data),
               State(db): State<Pool<Sqlite>>,
               State(crypto): State<MessageCrypto>| {
            let me = match current_user(&socket) {
                Ok(u) => u,
                Err(e) => {
                    ack.send(&ChannelSendResponse::Error {
                        reason: e.to_string(),
                    })
                    .ok();
                    return;
                }
            };
            match handle_channel_send(me, data, &crypto, &db).await {
                Ok((message, access)) => {
                    if let Err(e) = socket
                        .to(access.rooms())
                        .emit("channel_message", &message)
                        .await
                    {
                        error!("broadcast: {e:?}");
                    }
                    ack.send(&ChannelSendResponse::Ok { message }).ok();
                }
                Err(e) => {
                    ack.send(&ChannelSendResponse::Error {
                        reason: e.to_string(),
                    })
                    .ok();
                }
            }
        },
    );

    socket.on(
        "channel_sync",
        async |socket: SocketRef,
               ack: AckSender,
               Data::<ChannelSyncRequest>(data),
               State(db): State<Pool<Sqlite>>,
               State(crypto): State<MessageCrypto>| {
            let me = match current_user(&socket) {
                Ok(u) => u,
                Err(e) => {
                    ack.send(&ChannelSyncResponse::Error {
                        reason: e.to_string(),
                    })
                    .ok();
                    return;
                }
            };
            match handle_channel_sync(me, data, &crypto, &db).await {
                Ok(messages) => {
                    ack.send(&ChannelSyncResponse::Ok { messages }).ok();
                }
                Err(e) => {
                    ack.send(&ChannelSyncResponse::Error {
                        reason: e.to_string(),
                    })
                    .ok();
                }
            }
        },
    );

    socket.on(
        "channel_list",
        async |socket: SocketRef, ack: AckSender, State(db): State<Pool<Sqlite>>| {
            let me = match current_user(&socket) {
                Ok(u) => u,
                Err(e) => {
                    ack.send(&ChannelListResponse::Error {
                        reason: e.to_string(),
                    })
                    .ok();
                    return;
                }
            };
            match handle_channel_list(me, &db).await {
                Ok(channels) => {
                    ack.send(&ChannelListResponse::Ok { channels }).ok();
                }
                Err(e) => {
                    ack.send(&ChannelListResponse::Error {
                        reason: e.to_string(),
                    })
                    .ok();
                }
            }
        },
    );

    socket.on(
        "channel_rename",
        async |socket: SocketRef,
               ack: AckSender,
               Data::<ChannelRenameRequest>(data),
               State(db): State<Pool<Sqlite>>,
               State(admin): State<AdminId>| {
            let me = match current_user(&socket) {
                Ok(u) => u,
                Err(e) => {
                    ack.send(&ChannelRenameResponse::Error {
                        reason: e.to_string(),
                    })
                    .ok();
                    return;
                }
            };
            match handle_channel_rename(me, &data, &admin, &db).await {
                Ok(channel) => {
                    let _ = socket.to(TEXT_ROOM).emit("channel_renamed", &channel).await;
                    ack.send(&ChannelRenameResponse::Ok { channel }).ok();
                }
                Err(e) => {
                    ack.send(&ChannelRenameResponse::Error {
                        reason: e.to_string(),
                    })
                    .ok();
                }
            }
        },
    );

    socket.on(
        "channel_delete",
        async |socket: SocketRef,
               ack: AckSender,
               Data::<ChannelDeleteRequest>(data),
               State(db): State<Pool<Sqlite>>,
               State(admin): State<AdminId>| {
            let me = match current_user(&socket) {
                Ok(u) => u,
                Err(e) => {
                    ack.send(&ChannelDeleteResponse::Error {
                        reason: e.to_string(),
                    })
                    .ok();
                    return;
                }
            };
            match handle_channel_delete(me, &data, &admin, &db).await {
                Ok(()) => {
                    let payload = serde_json::json!({ "channel_id": data.channel_id });
                    let _ = socket.to(TEXT_ROOM).emit("channel_deleted", &payload).await;
                    ack.send(&ChannelDeleteResponse::Ok).ok();
                }
                Err(e) => {
                    ack.send(&ChannelDeleteResponse::Error {
                        reason: e.to_string(),
                    })
                    .ok();
                }
            }
        },
    );

    socket.on(
        "lookup_user",
        async |_socket: SocketRef,
               ack: AckSender,
               Data::<LookupUserRequest>(data),
               State(db): State<Pool<Sqlite>>| {
            match handle_lookup_user(data, &db).await {
                Ok((user_id, username)) => {
                    ack.send(&LookupUserResponse::Ok { user_id, username }).ok();
                }
                Err(e) => {
                    ack.send(&LookupUserResponse::Error {
                        reason: e.to_string(),
                    })
                    .ok();
                }
            }
        },
    );
}
