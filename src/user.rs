use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
pub struct UserDBData {
    pub user_id: Uuid,
    pub username: String,
    pub hashed_pw: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserLoginRequestData {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserRegisterRequestData {
    pub username: String,
    pub password: String,
}

#[derive(Clone)]
pub struct UserID(pub Uuid);
