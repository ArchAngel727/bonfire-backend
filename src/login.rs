use argon2::{
    Argon2, PasswordHash, PasswordVerifier,
    password_hash::rand_core::{OsRng, RngCore},
};
use socketioxide::{
    ParserError,
    extract::{AckSender, SocketRef, State, TryData},
};
use sqlx::{Pool, Sqlite};
use thiserror::Error;
use tracing::debug;
use uuid::Uuid;

use crate::{
    cookie::Cookie,
    crypto_manager::CryptoManager,
    session::Session,
    user::{UserDBData, UserLoginRequestData},
};

#[derive(Debug, Error)]
pub enum LoginError {
    #[error("AUTH_REQUIRED")]
    Missing,
    #[error("SESSION_INVALID")]
    Invalid,
    #[error("INTERNAL_ERROR {0}")]
    Internal(#[from] sqlx::Error),
}

async fn handle_login(
    socket: SocketRef,
    data: Result<UserLoginRequestData, ParserError>,
    db: &Pool<Sqlite>,
    crypto_manager: &CryptoManager,
) -> Result<Cookie, LoginError> {
    let data = data
        .inspect_err(|e| debug!("{:?}", e))
        .map_err(|_| LoginError::Missing)?;

    let user = match sqlx::query_as!(
        UserDBData,
        r#"SELECT
                user_id as "user_id: Uuid",
                username,
                hashed_pw
                FROM users WHERE username = ?1"#,
        data.username
    )
    .fetch_one(db)
    .await
    {
        Ok(user) => user,
        Err(e) => return Err(LoginError::Internal(e)),
    };

    let Ok(hash) = PasswordHash::new(&user.hashed_pw) else {
        return Err(LoginError::Invalid);
    };

    if Argon2::default()
        .verify_password(data.password.as_bytes(), &hash)
        .is_err()
    {
        return Err(LoginError::Invalid);
    }

    let mut session_id = [0; 16];
    let session = Session::new(user.user_id);

    OsRng.fill_bytes(&mut session_id);
    let signature = crypto_manager.sign(&session_id);
    let cookie = Cookie::new(session_id, signature);
    let session_id_bytes = &session_id[..];

    match sqlx::query!(
        r#"INSERT INTO sessions
                        (session_id, user_id, created_at, expires_at)
                        VALUES (?1, ?2, ?3, ?4)"#,
        session_id_bytes,
        session.user_id,
        session.created_at,
        session.expires_at,
    )
    .execute(db)
    .await
    {
        Ok(_) => {}
        Err(e) => return Err(LoginError::Internal(e)),
    };

    socket.extensions.insert(session.user_id);

    Ok(cookie)
}

pub async fn login(socket: SocketRef) {
    socket.on(
        "login",
        async |socket: SocketRef,
               ack: AckSender,
               TryData::<UserLoginRequestData>(data),
               State(db): State<Pool<Sqlite>>,
               State(crypto_manager): State<CryptoManager>| {
            match handle_login(socket, data, &db, &crypto_manager).await {
                Ok(cookie) => ack.send(&cookie).ok(),
                Err(e) => ack.send(&format!("{}", e)).ok(),
            };
        },
    );
}
