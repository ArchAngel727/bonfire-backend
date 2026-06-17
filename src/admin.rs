use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordVerifier, SaltString},
    Argon2, PasswordHasher,
};
use serde::{Deserialize, Serialize};
use socketioxide::extract::{AckSender, Data, SocketRef, State};
use sqlx::{Pool, Sqlite};
use std::fs::OpenOptions;
use std::io::Write;
use tracing::error;
use uuid::Uuid;

use crate::{
    permissions::{AdminId, is_mod},
    user::UserID,
};

pub fn load_admin_from_env() -> AdminId {
    let parsed = std::env::var("ADMIN_USER_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .and_then(|s| Uuid::parse_str(&s).ok());

    if let Some(id) = parsed {
        tracing::info!("admin loaded from env: {id}");
    } else {
        tracing::info!("no admin configured; first registered user will be promoted");
    }

    AdminId::new(parsed)
}

pub fn persist_admin_to_env(user_id: &Uuid) {
    match OpenOptions::new().create(true).append(true).open(".env") {
        Ok(mut f) => {
            if let Err(e) = writeln!(f, "ADMIN_USER_ID={user_id}") {
                tracing::error!("failed writing ADMIN_USER_ID to .env: {e}");
            } else {
                tracing::info!("persisted ADMIN_USER_ID={user_id} to .env");
            }
        }
        Err(e) => tracing::error!("could not open .env to persist admin: {e}"),
    }
}

fn current_user(socket: &SocketRef) -> Option<Uuid> {
    socket.extensions.get::<UserID>().map(|u| u.0)
}

#[derive(Deserialize, Debug)]
pub struct SetModRequest {
    pub user_id: Uuid,
    pub is_mod: bool,
}

#[derive(Serialize, Debug)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum SetModResponse {
    Ok,
    Error { reason: String },
}

#[derive(Serialize, Debug)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum MyRoleResponse {
    Ok {
        user_id: Uuid,
        is_admin: bool,
        is_mod: bool,
    },
    Error {
        reason: String,
    },
}

#[derive(Serialize, Debug)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum GetProfileResponse {
    Ok {
        user_id: Uuid,
        username: String,
        is_admin: bool,
        is_mod: bool,
    },
    Error {
        reason: String,
    },
}

#[derive(Deserialize, Debug)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Serialize, Debug)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum ChangePasswordResponse {
    Ok,
    Error { reason: String },
}

pub async fn admin(socket: SocketRef) {
    socket.on(
        "set_mod",
        async |socket: SocketRef,
               ack: AckSender,
               Data::<SetModRequest>(data),
               State(db): State<Pool<Sqlite>>,
               State(admin): State<AdminId>| {
            let Some(me) = current_user(&socket) else {
                ack.send(&SetModResponse::Error {
                    reason: "UNAUTHENTICATED".into(),
                })
                .ok();
                return;
            };

            if !admin.is(&me) {
                ack.send(&SetModResponse::Error {
                    reason: "FORBIDDEN".into(),
                })
                .ok();
                return;
            }

            if admin.is(&data.user_id) {
                ack.send(&SetModResponse::Error {
                    reason: "cannot set mod flag on the admin".into(),
                })
                .ok();
                return;
            }

            let flag: i64 = if data.is_mod { 1 } else { 0 };
            let res = sqlx::query!(
                "UPDATE users SET is_mod = ?1 WHERE user_id = ?2",
                flag,
                data.user_id
            )
            .execute(&db)
            .await;

            match res {
                Ok(r) if r.rows_affected() == 1 => {
                    ack.send(&SetModResponse::Ok).ok();
                }
                Ok(_) => {
                    ack.send(&SetModResponse::Error {
                        reason: "NOT_FOUND".into(),
                    })
                    .ok();
                }
                Err(e) => {
                    error!("set_mod db error: {e:?}");
                    ack.send(&SetModResponse::Error {
                        reason: "INTERNAL".into(),
                    })
                    .ok();
                }
            }
        },
    );

    socket.on(
        "my_role",
        async |socket: SocketRef,
               ack: AckSender,
               State(db): State<Pool<Sqlite>>,
               State(admin): State<AdminId>| {
            let Some(me) = current_user(&socket) else {
                ack.send(&MyRoleResponse::Error {
                    reason: "UNAUTHENTICATED".into(),
                })
                .ok();
                return;
            };

            let is_admin = admin.is(&me);
            let is_mod = if is_admin {
                false
            } else {
                match is_mod(&me, &db).await {
                    Ok(v) => v,
                    Err(e) => {
                        error!("my_role db error: {e:?}");
                        ack.send(&MyRoleResponse::Error {
                            reason: "INTERNAL".into(),
                        })
                        .ok();
                        return;
                    }
                }
            };

            ack.send(&MyRoleResponse::Ok {
                user_id: me,
                is_admin,
                is_mod,
            })
            .ok();
        },
    );

    socket.on(
        "get_profile",
        async |socket: SocketRef,
               ack: AckSender,
               State(db): State<Pool<Sqlite>>,
               State(admin): State<AdminId>| {
            let Some(me) = current_user(&socket) else {
                ack.send(&GetProfileResponse::Error {
                    reason: "UNAUTHENTICATED".into(),
                })
                .ok();
                return;
            };

            let row = match sqlx::query!(
                r#"SELECT username as "username!: String", is_mod as "is_mod!: i64"
                   FROM users WHERE user_id = ?1"#,
                me,
            )
            .fetch_optional(&db)
            .await
            {
                Ok(Some(r)) => r,
                Ok(None) => {
                    ack.send(&GetProfileResponse::Error {
                        reason: "user not found".into(),
                    })
                    .ok();
                    return;
                }
                Err(e) => {
                    error!("get_profile db error: {e:?}");
                    ack.send(&GetProfileResponse::Error {
                        reason: "INTERNAL".into(),
                    })
                    .ok();
                    return;
                }
            };

            let is_admin = admin.is(&me);

            ack.send(&GetProfileResponse::Ok {
                user_id: me,
                username: row.username,
                is_admin,
                is_mod: !is_admin && row.is_mod != 0,
            })
            .ok();
        },
    );

    socket.on(
        "change_password",
        async |socket: SocketRef,
               ack: AckSender,
               Data::<ChangePasswordRequest>(req),
               State(db): State<Pool<Sqlite>>| {
            let Some(me) = current_user(&socket) else {
                ack.send(&ChangePasswordResponse::Error {
                    reason: "UNAUTHENTICATED".into(),
                })
                .ok();
                return;
            };

            if req.new_password.len() < 6 {
                ack.send(&ChangePasswordResponse::Error {
                    reason: "new password must be at least 6 characters".into(),
                })
                .ok();
                return;
            }

            let current_hash = match sqlx::query_scalar!(
                "SELECT hashed_pw FROM users WHERE user_id = ?1",
                me,
            )
            .fetch_optional(&db)
            .await
            {
                Ok(Some(h)) => h,
                Ok(None) => {
                    ack.send(&ChangePasswordResponse::Error {
                        reason: "user not found".into(),
                    })
                    .ok();
                    return;
                }
                Err(e) => {
                    error!("change_password lookup: {e:?}");
                    ack.send(&ChangePasswordResponse::Error {
                        reason: "INTERNAL".into(),
                    })
                    .ok();
                    return;
                }
            };

            let parsed = match PasswordHash::new(&current_hash) {
                Ok(p) => p,
                Err(e) => {
                    error!("parse stored hash: {e:?}");
                    ack.send(&ChangePasswordResponse::Error {
                        reason: "INTERNAL".into(),
                    })
                    .ok();
                    return;
                }
            };

            if Argon2::default()
                .verify_password(req.old_password.as_bytes(), &parsed)
                .is_err()
            {
                ack.send(&ChangePasswordResponse::Error {
                    reason: "current password is incorrect".into(),
                })
                .ok();
                return;
            }

            let salt = SaltString::generate(&mut OsRng);
            let new_hash = match Argon2::default()
                .hash_password(req.new_password.as_bytes(), &salt)
            {
                Ok(h) => h.to_string(),
                Err(e) => {
                    error!("hash new password: {e:?}");
                    ack.send(&ChangePasswordResponse::Error {
                        reason: "INTERNAL".into(),
                    })
                    .ok();
                    return;
                }
            };

            let res = sqlx::query!(
                "UPDATE users SET hashed_pw = ?1 WHERE user_id = ?2",
                new_hash,
                me,
            )
            .execute(&db)
            .await;

            match res {
                Ok(_) => {
                    ack.send(&ChangePasswordResponse::Ok).ok();
                }
                Err(e) => {
                    error!("update password: {e:?}");
                    ack.send(&ChangePasswordResponse::Error {
                        reason: "INTERNAL".into(),
                    })
                    .ok();
                }
            }
        },
    );
}
