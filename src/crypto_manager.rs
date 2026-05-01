use std::env;

use crate::cookie::{Cookie, SignedCookie};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct CryptoManager {}

impl CryptoManager {
    pub fn sign_cookie(cookie: &Cookie) -> Option<String> {
        if let Ok(secret) = env::var("SECRET") {
            let payload = serde_json::to_string(cookie).unwrap();

            let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
            mac.update(payload.as_bytes());
            Some(hex::encode(mac.finalize().into_bytes()))
        } else {
            None
        }
    }

    pub fn check_cookie(signed_cookie: &SignedCookie) -> bool {
        if let Ok(secret) = env::var("SECRET") {
            let payload = serde_json::to_string(&signed_cookie.cookie).unwrap();
            let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
            mac.update(payload.as_bytes());

            mac.verify_slice(&hex::decode(&signed_cookie.signiture).unwrap_or_default())
                .is_ok()
        } else {
            false
        }
    }
}
