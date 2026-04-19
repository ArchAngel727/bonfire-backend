use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use socketioxide::extract::{AckSender, Data, SocketRef, State};
use sqlx::{Pool, Sqlite};
use tracing::{error, info};
use uuid::Uuid;

use crate::user::UserRequestData;

pub async fn register(socket: SocketRef) {
    info!("Connected to {:?} with id {:?}", socket.ns(), socket.id);

    socket.on(
        "register",
        async |Data::<UserRequestData>(data), ack: AckSender, db: State<Pool<Sqlite>>| {
            let user_id = Uuid::new_v4().into_bytes().to_vec();

            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let hashed_password = argon2.hash_password(data.password.as_bytes(), &salt);

            info!("{:?}", hashed_password);

            let db_response = sqlx::query!(
                "INSERT INTO users (user_id, username, hashed_pw) values (?1, ?2, ?3)",
                user_id,
                data.username,
                data.password
            )
            .execute(&*db)
            .await;

            match db_response {
                Ok(result) => {
                    info!("{:?}", result);
                    ack.send(&user_id).ok();
                }
                Err(err) => {
                    error!("{:?}", err);
                    ack.send("Error").ok();
                }
            }
        },
    );
}
