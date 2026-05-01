use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct UserDBData {
    user_id: Vec<u8>,
    username: String,
    hashed_pw: String,
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
