use argon2::{
    Argon2, PasswordHasher,
    password_hash::{SaltString, rand_core::OsRng},
};
use socketioxide::extract::{AckSender, Data, SocketRef, State};
use sqlx::{Pool, Sqlite};
use tracing::{error, info};
use uuid::Uuid;

use crate::{admin::persist_admin_to_env, permissions::AdminId, user::UserRegisterRequestData};

pub async fn register(socket: SocketRef) {
    socket.on(
        "register",
        async |Data::<UserRegisterRequestData>(data),
               ack: AckSender,
               db: State<Pool<Sqlite>>,
               State(admin): State<AdminId>| {
            let user_uuid = Uuid::new_v4();
            let user_id = user_uuid.into_bytes().to_vec();

            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let hashed_password = argon2.hash_password(data.password.as_bytes(), &salt);

            if let Ok(password_hash) = hashed_password {
                let pwd_hash = password_hash.to_string();

                let db_response = sqlx::query!(
                    "INSERT INTO users (user_id, username, hashed_pw) values (?1, ?2, ?3)",
                    user_id,
                    data.username,
                    pwd_hash
                )
                .execute(&*db)
                .await;

                match db_response {
                    Ok(result) => {
                        info!("{:?}", result);

                        if admin.is_unset() {
                            admin.set(user_uuid);
                            persist_admin_to_env(&user_uuid);
                            info!("Bootstraping admin");
                        }

                        ack.send(&user_id).ok();
                    }
                    Err(err) => {
                        error!("{:?}", err);
                        ack.send("Error").ok();
                    }
                }
            }
        },
    );
}
