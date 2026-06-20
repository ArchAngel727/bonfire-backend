use serde::{Deserialize, Serialize};
use socketioxide::extract::{AckSender, Data, SocketRef, State};
use sqlx::{Pool, Sqlite};
use tracing::error;
use uuid::Uuid;

use crate::user::UserID;

fn current_user(socket: &SocketRef) -> Option<Uuid> {
    socket.extensions.get::<UserID>().map(|u| u.0)
}

// ─── upload_bundle ──────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct OneTimePrekeyUpload {
    pub prekey_id: i64,
    pub public_key: Vec<u8>,
}

#[derive(Deserialize, Debug)]
pub struct UploadBundleRequest {
    pub identity_key: Vec<u8>,
    pub signing_key: Vec<u8>,
    pub signed_prekey: Vec<u8>,
    pub signed_prekey_signature: Vec<u8>,
    pub signed_prekey_id: i64,
    pub one_time_prekeys: Vec<OneTimePrekeyUpload>,
}

#[derive(Serialize, Debug)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum UploadBundleResponse {
    Ok { one_time_prekey_count: i64 },
    Error { reason: String },
}

// ─── fetch_bundle ───────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct FetchBundleRequest {
    pub user_id: Uuid,
}

#[derive(Serialize, Debug)]
pub struct FetchedOneTimePrekey {
    pub prekey_id: i64,
    pub public_key: Vec<u8>,
}

#[derive(Serialize, Debug)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum FetchBundleResponse {
    Ok {
        user_id: Uuid,
        identity_key: Vec<u8>,
        signing_key: Vec<u8>,
        signed_prekey: Vec<u8>,
        signed_prekey_signature: Vec<u8>,
        signed_prekey_id: i64,
        /// None if this user has no one-time prekeys left. Client should
        /// fall back to using only the signed prekey for the initial X3DH.
        one_time_prekey: Option<FetchedOneTimePrekey>,
    },
    Error {
        reason: String,
    },
}

// ─── prekey_count (debug helper for today's smoke test) ──────────────

#[derive(Serialize, Debug)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum PrekeyCountResponse {
    Ok { count: i64 },
    Error { reason: String },
}

// ─── handlers ───────────────────────────────────────────────────────

async fn handle_upload_bundle(
    me: Uuid,
    req: UploadBundleRequest,
    db: &Pool<Sqlite>,
) -> Result<i64, String> {
    // Quick sanity on lengths so we fail loudly rather than store junk.
    if req.identity_key.len() != 32 {
        return Err("identity_key must be 32 bytes".into());
    }
    if req.signing_key.len() != 32 {
        return Err("signing_key must be 32 bytes".into());
    }
    if req.signed_prekey.len() != 32 {
        return Err("signed_prekey must be 32 bytes".into());
    }
    if req.signed_prekey_signature.len() != 64 {
        return Err("signed_prekey_signature must be 64 bytes".into());
    }
    for k in &req.one_time_prekeys {
        if k.public_key.len() != 32 {
            return Err(format!("one-time prekey {} must be 32 bytes", k.prekey_id));
        }
    }

    let now = chrono::Utc::now().timestamp();
    let mut tx = db.begin().await.map_err(|e| {
        error!("upload_bundle tx begin: {e:?}");
        "INTERNAL".to_string()
    })?;

    sqlx::query!(
        "INSERT OR REPLACE INTO key_bundles
           (user_id, identity_key, signing_key, signed_prekey,
            signed_prekey_signature, signed_prekey_id, uploaded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        me,
        req.identity_key,
        req.signing_key,
        req.signed_prekey,
        req.signed_prekey_signature,
        req.signed_prekey_id,
        now,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("upload_bundle insert bundle: {e:?}");
        "INTERNAL".to_string()
    })?;

    // Wipe the existing one-time prekey pool for this user — a re-upload
    // means the client has a fresh account; old prekeys are no longer valid.
    sqlx::query!("DELETE FROM one_time_prekeys WHERE user_id = ?1", me)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("upload_bundle wipe prekeys: {e:?}");
            "INTERNAL".to_string()
        })?;

    for k in &req.one_time_prekeys {
        sqlx::query!(
            "INSERT INTO one_time_prekeys (user_id, prekey_id, public_key)
             VALUES (?1, ?2, ?3)",
            me,
            k.prekey_id,
            k.public_key,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("upload_bundle insert prekey: {e:?}");
            "INTERNAL".to_string()
        })?;
    }

    tx.commit().await.map_err(|e| {
        error!("upload_bundle commit: {e:?}");
        "INTERNAL".to_string()
    })?;

    Ok(req.one_time_prekeys.len() as i64)
}

async fn handle_fetch_bundle(
    target: Uuid,
    db: &Pool<Sqlite>,
) -> Result<FetchBundleResponse, String> {
    let bundle = sqlx::query!(
        r#"SELECT
            identity_key as "identity_key!: Vec<u8>",
            signing_key as "signing_key!: Vec<u8>",
            signed_prekey as "signed_prekey!: Vec<u8>",
            signed_prekey_signature as "signed_prekey_signature!: Vec<u8>",
            signed_prekey_id as "signed_prekey_id!: i64"
           FROM key_bundles WHERE user_id = ?1"#,
        target,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| {
        error!("fetch_bundle lookup: {e:?}");
        "INTERNAL".to_string()
    })?;

    let Some(bundle) = bundle else {
        return Err("no bundle uploaded for that user yet".into());
    };

    // Atomically pop one one-time prekey. SQLite doesn't support
    // RETURNING in older sqlx versions, so we do SELECT then DELETE in
    // a transaction.
    let mut tx = db.begin().await.map_err(|e| {
        error!("fetch_bundle tx begin: {e:?}");
        "INTERNAL".to_string()
    })?;

    let one_time = sqlx::query!(
        r#"SELECT
            prekey_id as "prekey_id!: i64",
            public_key as "public_key!: Vec<u8>"
           FROM one_time_prekeys
           WHERE user_id = ?1
           ORDER BY prekey_id ASC
           LIMIT 1"#,
        target,
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        error!("fetch_bundle pick prekey: {e:?}");
        "INTERNAL".to_string()
    })?;

    let consumed = if let Some(p) = one_time {
        sqlx::query!(
            "DELETE FROM one_time_prekeys WHERE user_id = ?1 AND prekey_id = ?2",
            target,
            p.prekey_id,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("fetch_bundle delete prekey: {e:?}");
            "INTERNAL".to_string()
        })?;
        Some(FetchedOneTimePrekey {
            prekey_id: p.prekey_id,
            public_key: p.public_key,
        })
    } else {
        None
    };

    tx.commit().await.map_err(|e| {
        error!("fetch_bundle commit: {e:?}");
        "INTERNAL".to_string()
    })?;

    Ok(FetchBundleResponse::Ok {
        user_id: target,
        identity_key: bundle.identity_key,
        signing_key: bundle.signing_key,
        signed_prekey: bundle.signed_prekey,
        signed_prekey_signature: bundle.signed_prekey_signature,
        signed_prekey_id: bundle.signed_prekey_id,
        one_time_prekey: consumed,
    })
}

async fn handle_prekey_count(me: Uuid, db: &Pool<Sqlite>) -> Result<i64, String> {
    sqlx::query_scalar!(
        r#"SELECT COUNT(*) as "count!: i64" FROM one_time_prekeys WHERE user_id = ?1"#,
        me,
    )
    .fetch_one(db)
    .await
    .map_err(|e| {
        error!("prekey_count: {e:?}");
        "INTERNAL".to_string()
    })
}

// ─── socket wiring ──────────────────────────────────────────────────

pub async fn keys(socket: SocketRef) {
    socket.on(
        "upload_bundle",
        async |socket: SocketRef,
               ack: AckSender,
               Data::<UploadBundleRequest>(data),
               State(db): State<Pool<Sqlite>>| {
            let Some(me) = current_user(&socket) else {
                ack.send(&UploadBundleResponse::Error {
                    reason: "UNAUTHENTICATED".into(),
                })
                .ok();
                return;
            };
            match handle_upload_bundle(me, data, &db).await {
                Ok(n) => {
                    ack.send(&UploadBundleResponse::Ok {
                        one_time_prekey_count: n,
                    })
                    .ok();
                }
                Err(reason) => {
                    ack.send(&UploadBundleResponse::Error { reason }).ok();
                }
            }
        },
    );

    socket.on(
        "fetch_bundle",
        async |socket: SocketRef,
               ack: AckSender,
               Data::<FetchBundleRequest>(data),
               State(db): State<Pool<Sqlite>>| {
            if current_user(&socket).is_none() {
                ack.send(&FetchBundleResponse::Error {
                    reason: "UNAUTHENTICATED".into(),
                })
                .ok();
                return;
            }
            match handle_fetch_bundle(data.user_id, &db).await {
                Ok(resp) => {
                    ack.send(&resp).ok();
                }
                Err(reason) => {
                    ack.send(&FetchBundleResponse::Error { reason }).ok();
                }
            }
        },
    );

    socket.on(
        "prekey_count",
        async |socket: SocketRef, ack: AckSender, State(db): State<Pool<Sqlite>>| {
            let Some(me) = current_user(&socket) else {
                ack.send(&PrekeyCountResponse::Error {
                    reason: "UNAUTHENTICATED".into(),
                })
                .ok();
                return;
            };
            match handle_prekey_count(me, &db).await {
                Ok(count) => {
                    ack.send(&PrekeyCountResponse::Ok { count }).ok();
                }
                Err(reason) => {
                    ack.send(&PrekeyCountResponse::Error { reason }).ok();
                }
            }
        },
    );
}
