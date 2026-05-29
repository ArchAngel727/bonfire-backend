mod admin;
mod auth;
mod auth_middlewear;
mod channel;
mod channels;
mod cookie;
mod crypto_manager;
mod login;
mod messages;
mod permissions;
mod register;
mod session;
mod user;

use std::time::Duration;

use axum::routing::get;
use chrono::Utc;
use dotenv::dotenv;
use serde_json::Value;
use socketioxide::{
    SocketIo,
    extract::{Data, SocketRef},
    handler::ConnectHandler,
};
use sqlx::{Pool, Sqlite, sqlite::SqlitePoolOptions};
use tokio::time::interval;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tracing::info;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use crate::{
    admin::{admin, load_admin_from_env},
    auth::auth,
    auth_middlewear::auth_middlewear,
    crypto_manager::CryptoManager,
    login::login,
    messages::message,
    register::register,
};

async fn root(socket: SocketRef, Data(_): Data<Value>) {
    info!("Connected to {:?} with id {:?}", socket.ns(), socket.id);

    socket.on_disconnect(async |socket: SocketRef| {
        info!("Disconnect {:?}", socket.ns());
    });
}

async fn spawn_ticker(db: Pool<Sqlite>) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(300));
        loop {
            ticker.tick().await;
            let now = Utc::now();

            if let Err(e) = sqlx::query!("DELETE FROM sessions WHERE expires_at < ?1", now)
                .execute(&db)
                .await
            {
                tracing::error!("session clean failed: {}", e);
            }
        }
    });
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing::subscriber::set_global_default(
        FmtSubscriber::builder().with_env_filter(filter).finish(),
    )?;

    dotenv()?;

    let cm = CryptoManager::from_env()?;
    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .min_connections(1)
        .connect("sqlite://./data/db.sqlite")
        .await?;

    sqlx::migrate!().run(&db).await?;
    spawn_ticker(db.clone()).await;

    let admin_id = load_admin_from_env();

    let (layer, io) = SocketIo::builder()
        .max_payload(10_000_000)
        .max_buffer_size(10_000)
        .with_state(db.clone())
        .with_state(cm.clone())
        .with_state(admin_id)
        .build_layer();

    io.ns("/", root);
    io.ns("/message", message);
    io.ns("/login", login);
    io.ns("/register", register);
    io.ns("/auth", auth.with(auth_middlewear));
    io.ns("/admin", admin.with(auth_middlewear));

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
