use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{rand_core::RngCore, SaltString},
    Argon2, Params, PasswordHasher, Version,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use zeroize::Zeroize;

pub const NONCE_SIZE: usize = 12; // 96 bits pour AES-GCM

#[derive(Debug)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidKey,
    KdfError(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::EncryptionFailed => write!(f, "Échec du chiffrement"),
            CryptoError::DecryptionFailed => write!(f, "Échec du déchiffrement (mot de passe incorrect?)"),
            CryptoError::InvalidKey => write!(f, "Clé invalide"),
            CryptoError::KdfError(e) => write!(f, "Erreur KDF: {}", e),
        }
    }
}

impl std::error::Error for CryptoError {}

pub struct CryptoParams {
    pub time_cost: u32,
    pub memory_cost: u32,
    pub parallelism: u32,
}

impl Default for CryptoParams {
    fn default() -> Self {
        Self {
            time_cost: 2,
            memory_cost: 65536, // 64 MiB
            parallelism: 1,
        }
    }
}

/// Dérive une clé de 256 bits depuis un mot de passe avec Argon2id
pub fn derive_key(
    password: &str,
    salt: &[u8],
    params: &CryptoParams,
) -> Result<Vec<u8>, CryptoError> {
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;

    // Créer les paramètres Argon2
    let argon2_params = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(32), // Output length: 32 bytes (256 bits)
    )
    .map_err(|e| CryptoError::KdfError(e.to_string()))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        argon2_params,
    );

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;

    let hash = password_hash.hash
        .ok_or_else(|| CryptoError::KdfError("No hash generated".to_string()))?;

    Ok(hash.as_bytes().to_vec())
}

/// Génère un salt aléatoire
pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Génère un nonce aléatoire
pub fn generate_nonce() -> Vec<u8> {
    let mut nonce = vec![0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Chiffre des données avec AES-256-GCM
pub fn encrypt(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    if nonce.len() != NONCE_SIZE {
        return Err(CryptoError::EncryptionFailed);
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKey)?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .encrypt(nonce, data)
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Déchiffre des données avec AES-256-GCM
pub fn decrypt(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    if nonce.len() != NONCE_SIZE {
        return Err(CryptoError::DecryptionFailed);
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKey)?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Wrapper sécurisé pour la clé de chiffrement (zeroize on drop)
pub struct SecureKey {
    key: Vec<u8>,
}

impl SecureKey {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Encode en base64
pub fn encode_base64(data: &[u8]) -> String {
    BASE64.encode(data)
}

/// Décode depuis base64
pub fn decode_base64(data: &str) -> Result<Vec<u8>, CryptoError> {
    BASE64.decode(data)
        .map_err(|_| CryptoError::DecryptionFailed)
}