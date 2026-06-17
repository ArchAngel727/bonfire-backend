// src/message_crypto.rs
//
// Server-side encryption for text channel content at rest.
//
// Storage format per message: [12-byte nonce] || [ciphertext + 16-byte tag].
// Key: 32 bytes (AES-256), loaded from `./data/message.key` or generated on
// first boot and written there with 0600 permissions on unix.
//
// Phase 2 scope: text channels only. DMs bypass this entirely (the server
// stores whatever bytes the client sent — which becomes Olm ciphertext in
// phase 4, but is plaintext for now).

use std::fs;
use std::path::Path;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use thiserror::Error;
use tracing::info;

#[derive(Debug, Error)]
pub enum MessageCryptoError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encryption/decryption failed")]
    Crypto,
    #[error("keyfile has invalid size (expected 32 bytes)")]
    KeyfileSize,
    #[error("ciphertext blob too short")]
    BlobTooShort,
}

#[derive(Clone)]
pub struct MessageCrypto {
    cipher: Aes256Gcm,
}

impl MessageCrypto {
    /// Load the key from `path`. If the file doesn't exist, generate a fresh
    /// 32-byte key with the OS RNG, write it to `path` (creating parents),
    /// and set 0600 permissions on unix. The key file is the entire backup
    /// surface for text channel content — lose it and the messages are
    /// unrecoverable. Don't check it into git.
    pub fn load_or_create(path: &Path) -> Result<Self, MessageCryptoError> {
        let key_bytes: Vec<u8> = if path.exists() {
            let bytes = fs::read(path)?;
            if bytes.len() != 32 {
                return Err(MessageCryptoError::KeyfileSize);
            }
            info!("message encryption key loaded from {}", path.display());
            bytes
        } else {
            let key = Aes256Gcm::generate_key(&mut OsRng);
            let bytes = key.to_vec();
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, &bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(path)?.permissions();
                perms.set_mode(0o600);
                fs::set_permissions(path, perms)?;
            }
            info!("generated new message encryption key at {}", path.display());
            bytes
        };

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        Ok(Self { cipher })
    }

    /// Encrypt plaintext. Fresh random nonce per call. Output is
    /// nonce (12 bytes) || ciphertext+tag.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, MessageCryptoError> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| MessageCryptoError::Crypto)?;
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a blob produced by `encrypt`. Returns the original plaintext
    /// or an error if the blob is malformed / the tag fails / the key is wrong.
    pub fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>, MessageCryptoError> {
        if blob.len() < 12 + 16 {
            return Err(MessageCryptoError::BlobTooShort);
        }
        let (nonce_bytes, ciphertext) = blob.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| MessageCryptoError::Crypto)
    }
}
