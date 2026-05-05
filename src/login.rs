use ::uuid::Uuid;
use argon2::{
    Argon2, PasswordHash, PasswordVerifier,
    password_hash::rand_core::{OsRng, RngCore},
};
use socketioxide::extract::{AckSender, Data, SocketRef, State};
use sqlx::{Pool, Sqlite};
use tracing::info;

use crate::{
    cookie::Cookie,
    crypto_manager::CryptoManager,
    session::Session,
    user::{UserDBData, UserLoginRequestData},
};

pub async fn login(socket: SocketRef) {
    socket.on(
        "login",
        async |Data::<UserLoginRequestData>(data),
               ack: AckSender,
               State(db): State<Pool<Sqlite>>,
               State(crypto_manager): State<CryptoManager>| {
            info!("on login, data: {:?}", data);

            // TODO: Extract into validate_user()
            if let Ok(user) = sqlx::query_as!(
                UserDBData,
                r#"SELECT
                user_id as "user_id: Uuid",
                username,
                hashed_pw
                FROM users WHERE username = ?1"#,
                data.username
            )
            .fetch_one(&db)
            .await
            {
                let Ok(hash) = PasswordHash::new(&user.hashed_pw) else {
                    ack.send("Error").ok();
                    return;
                };

                if Argon2::default()
                    .verify_password(data.password.as_bytes(), &hash)
                    .is_ok()
                {
                    let mut session_id = [0; 16];
                    let session = Session::new(user.user_id);

                    OsRng.fill_bytes(&mut session_id);
                    let signature = crypto_manager.sign(&session_id);
                    let cookie = Cookie::new(session_id, signature);
                    let session_id_bytes = &session_id[..];

                    let _ = sqlx::query!(
                        "INSERT INTO sessions (session_id, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
                        session_id_bytes,
                        session.user_id,
                        session.created_at,
                        session.expires_at,
                    )
                    .execute(&db)
                    .await;

                    ack.send(&cookie).ok();
                } else {
                    ack.send("Invalid login data").ok();
                }
            }
        },
    );
}
