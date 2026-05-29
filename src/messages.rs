use serde_json::Value;
use socketioxide::extract::{AckSender, Data, SocketRef};
use tracing::info;

pub async fn message(socket: SocketRef) {
    socket.on("message", async |ack: AckSender, Data::<Value>(data)| {
        info!("on message-with-ack, data: {:?}", data);
        ack.send(&format!("test {}", &data)).ok();
    });

    socket.on("ping", async |Data::<Value>(_data), ack: AckSender| {
        eprintln!("Hell yeah momenat");
        ack.send(&"pong").ok();
    });
}
