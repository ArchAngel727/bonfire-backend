use argon2::{Argon2, PasswordHash, PasswordVerifier};
use socketioxide::extract::{AckSender, Data, SocketRef, State};
use sqlx::{Pool, Sqlite};
use tracing::info;

use crate::{
    cookie::{Cookie, SignedCookie},
    user::UserLoginRequestData,
};

pub async fn login(socket: SocketRef) {
    socket.on(
        "login",
        async |Data::<UserLoginRequestData>(data), ack: AckSender, db: State<Pool<Sqlite>>| {
            info!("on login, data: {:?}", data);

            if let Ok(user) = sqlx::query!(
                "SELECT * FROM users WHERE users.username = ?1",
                data.username
            )
            .fetch_one(&*db)
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
                    let Some(id) = user.user_id else {
                        ack.send("500").ok();
                        return;
                    };

                    let cookie = Cookie::new(id.try_into().unwrap());
                    let sc = SignedCookie::new(cookie);
                    ack.send(&sc).ok();
                } else {
                    ack.send("Invalid login data").ok();
                }
            }
        },
    );
}
