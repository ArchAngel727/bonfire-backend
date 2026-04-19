use argon2::{Argon2, PasswordHash, PasswordVerifier};
use socketioxide::extract::{AckSender, Data, SocketRef, State};
use sqlx::{Pool, Sqlite};
use tracing::info;

use crate::user::UserRequestData;

pub async fn login(socket: SocketRef) {
    info!("Connected to {:?} with id {:?}", socket.ns(), socket.id);

    socket.on(
        "login",
        async |Data::<UserRequestData>(data), ack: AckSender, db: State<Pool<Sqlite>>| {
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
                    ack.send("Login complete").ok();
                } else {
                    ack.send("Invalid login data").ok();
                }
            }
        },
    );
}
