use serde_json::Value;
use socketioxide::extract::{AckSender, Data, SocketRef};
use tracing::info;

pub async fn message(socket: SocketRef) {
    info!("Connected to {:?} with id {:?}", socket.ns(), socket.id);

    socket.on("message", async |Data::<Value>(data), ack: AckSender| {
        info!("on message-with-ack, data: {:?}", data);
        ack.send(&format!("test {}", &data)).ok();
    });
}
