mod auth;
mod cookie;
mod crypto_manager;
mod login;
mod messages;
mod register;
mod session;
mod user;

use axum::routing::get;
use dotenv::dotenv;
use serde_json::Value;
use socketioxide::{
    SocketIo,
    extract::{Data, SocketRef},
};
use sqlx::sqlite::SqlitePoolOptions;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tracing::info;
use tracing_subscriber::FmtSubscriber;

use crate::{
    auth::auth, crypto_manager::CryptoManager, login::login, messages::message, register::register,
};

async fn root(socket: SocketRef, Data(_): Data<Value>) {
    info!("Connected to {:?} with id {:?}", socket.ns(), socket.id);

    socket.on_disconnect(async |socket: SocketRef| {
        info!("Disconnect {:?}", socket.ns());
    });
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing::subscriber::set_global_default(FmtSubscriber::default())?;

    dotenv()?;

    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .min_connections(1)
        .connect("sqlite://./data/users.sqlite")
        .await?;

    let cm = CryptoManager::from_env()?;

    sqlx::migrate!().run(&db).await?;

    let (layer, io) = SocketIo::builder()
        .max_payload(10_000_000)
        .max_buffer_size(10_000)
        .with_state(db.clone())
        .with_state(cm.clone())
        .build_layer();

    io.ns("/", root);
    io.ns("/message", message);
    io.ns("/login", login);
    io.ns("/register", register);
    io.ns("/auth", auth);

    let app = axum::Router::new()
        .route("/", get(|| async { "Hello, World" }))
        .layer(
            ServiceBuilder::new()
                .layer(CorsLayer::permissive())
                .layer(layer),
        );

    info!("Starting server");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
