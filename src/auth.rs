use socketioxide::extract::{AckSender, Data, SocketRef, State};
use sqlx::{Pool, Sqlite};

use crate::{cookie::SignedCookie, crypto_manager::CryptoManager};

pub async fn auth(socket: SocketRef) {
    socket.on(
        "request_new_session",
        async |Data::<SignedCookie>(data), ack: AckSender, _db: State<Pool<Sqlite>>| {
            ack.send(&CryptoManager::check_cookie(&data)).ok();
        },
    );
}
