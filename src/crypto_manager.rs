use std::env;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("SECRET environment variable not set")]
    MissingSecret,
    #[error("SECRET is empty")]
    EmptySecret,
}

#[derive(Clone)]
pub struct CryptoManager {
    key: Vec<u8>,
}

impl CryptoManager {
    pub fn from_env() -> Result<Self, CryptoError> {
        let secret = env::var("SECRET").map_err(|_| CryptoError::MissingSecret)?;
        if secret.is_empty() {
            return Err(CryptoError::EmptySecret);
        }

        Ok(Self {
            key: secret.into_bytes(),
        })
    }

    pub fn sign(&self, session_id: &[u8; 16]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC error");
        Mac::update(&mut mac, session_id);
        mac.finalize().into_bytes().into()
    }

    pub fn verify(&self, session_id: &[u8; 16], signature: &[u8; 32]) -> bool {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        Mac::update(&mut mac, session_id);
        mac.verify_slice(signature).is_ok()
    }
}
