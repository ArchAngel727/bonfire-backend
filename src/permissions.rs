use std::sync::{Arc, RwLock};

use sqlx::{Pool, Sqlite};
use uuid::Uuid;

#[derive(Clone)]
pub struct AdminId(Arc<RwLock<Option<Uuid>>>);

impl AdminId {
    pub fn new(id: Option<Uuid>) -> Self {
        Self(Arc::new(RwLock::new(id)))
    }

    pub fn get(&self) -> Option<Uuid> {
        self.0.read().ok().and_then(|g| *g)
    }

    pub fn set(&self, id: Uuid) {
        if let Ok(mut g) = self.0.write() {
            *g = Some(id);
        }
    }

    pub fn is_unset(&self) -> bool {
        self.get().is_none()
    }

    pub fn is(&self, user_id: &Uuid) -> bool {
        self.get().as_ref() == Some(user_id)
    }
}

pub async fn is_mod(user_id: &Uuid, db: &Pool<Sqlite>) -> Result<bool, sqlx::Error> {
    let row = sqlx::query_scalar!(
        r#"SELECT is_mod as "is_mod!: i64" FROM users WHERE user_id = ?1"#,
        user_id
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|v| v != 0).unwrap_or(false))
}

pub async fn is_staff(
    user_id: &Uuid,
    admin: &AdminId,
    db: &Pool<Sqlite>,
) -> Result<bool, sqlx::Error> {
    if admin.is(user_id) {
        return Ok(true);
    }
    is_mod(user_id, db).await
}

pub async fn can_create_text_channel(
    user_id: &Uuid,
    admin: &AdminId,
    db: &Pool<Sqlite>,
) -> Result<bool, sqlx::Error> {
    match std::env::var("CHANNEL_CREATE_MIN_ROLE")
        .unwrap_or_else(|_| String::from("admin"))
        .as_str()
    {
        "user" => Ok(true),
        "mod" => is_staff(user_id, admin, db).await,
        _ => Ok(admin.is(user_id)),
    }
}
