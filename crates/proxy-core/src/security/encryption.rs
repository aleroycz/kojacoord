//! Pluggable AEAD cipher registry, plus an experimental post-quantum
//! KEM hook.
//!
//! Minecraft's wire protocol uses AES-128-CFB8 for the Login session
//! key exchange — that's handled in `auth::encryption` and not
//! changeable. This module is for *secondary* encryption: configurable
//! ciphers we use to wrap inter-node communication (cluster gossip,
//! control-plane payloads, etc.) where operators want algorithm agility.
//!
//! The PQ branch is exploratory; the implementation below is a
//! Kyber-shaped placeholder rather than a real KEM. Do not enable it
//! in production until it's swapped for `pqcrypto-kyber` or equivalent.

use aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use rand::{rngs::OsRng, RngCore};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Algorithm discriminant used by [`EncryptionManager`] to dispatch to
/// the concrete `Cipher` implementation. `Custom(u32)` is reserved for
/// operator-defined algorithms registered at runtime; the integer is
/// caller-meaningful only.
///
/// ## Minecraft compatibility
///
/// **NONE of these variants are speakable on the Minecraft Java wire.**
/// Vanilla Java Edition clients (1.7 → 1.21.x) handle the session
/// handshake by mandate at AES-128/CFB8 with key == IV == shared
/// secret — that's `auth::encryption` and isn't swappable. The
/// variants here are for proxy-internal channels (DB column crypto,
/// cluster gossip, plugin transport) where the proxy controls BOTH
/// ends and can negotiate freely. If you pipe one of these through a
/// Minecraft client socket, the client will see noise and disconnect.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncryptionAlgorithm {
    /// AES-256-GCM (current standard)
    Aes256Gcm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
    /// XChaCha20-Poly1305 (extended nonce)
    XChaCha20Poly1305,
    /// Post-quantum KEM (experimental - Kyber)
    PostQuantumKem,
    /// Custom/unknown
    Custom(u32),
}

/// Self-describing key bundle: algorithm tag + raw bytes + a stable
/// `key_id` for log correlation. `nonce` is carried alongside the key
/// because AEAD callers usually need both available together; rotating
/// the nonce per-message is the caller's responsibility.
#[derive(Debug)]
pub struct EncryptionKey {
    pub algorithm: EncryptionAlgorithm,
    pub key_data: Vec<u8>,
    pub key_id: String,
    pub nonce: Option<Vec<u8>>,
    counter: AtomicU64,
}

impl EncryptionKey {
    pub fn new(algorithm: EncryptionAlgorithm, key_data: Vec<u8>, key_id: String) -> Self {
        Self {
            algorithm,
            key_data,
            key_id,
            nonce: None,
            counter: AtomicU64::new(0),
        }
    }

    pub fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn derive_nonce(&self) -> Option<(Vec<u8>, u64)> {
        let base = self.nonce.as_ref()?;
        let ctr = self.counter.fetch_add(1, Ordering::Relaxed);
        let derived = xor_nonce_with_counter(base, ctr);
        Some((derived, ctr))
    }

    /// Mint a fresh random key (and nonce, for AEAD algorithms) from
    /// `OsRng`. Errors only on `Custom(_)` — we can't guess a key size
    /// for an algorithm we don't know.
    pub fn generate(algorithm: EncryptionAlgorithm) -> Result<Self, String> {
        let key_size = match algorithm {
            EncryptionAlgorithm::Aes256Gcm => 32,
            EncryptionAlgorithm::ChaCha20Poly1305 => 32,
            EncryptionAlgorithm::XChaCha20Poly1305 => 32,
            EncryptionAlgorithm::PostQuantumKem => 32, // Kyber-512 key size
            EncryptionAlgorithm::Custom(size) => {
                return Err(format!(
                    "Custom algorithm requires explicit key size, got {}",
                    size
                ))
            },
        };

        let mut key_data = vec![0u8; key_size];
        OsRng.fill_bytes(&mut key_data);

        // Generate nonce for AEAD ciphers
        let nonce = match algorithm {
            EncryptionAlgorithm::Aes256Gcm => {
                let mut nonce = vec![0u8; 12];
                OsRng.fill_bytes(&mut nonce);
                Some(nonce)
            },
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                let mut nonce = vec![0u8; 12];
                OsRng.fill_bytes(&mut nonce);
                Some(nonce)
            },
            EncryptionAlgorithm::XChaCha20Poly1305 => {
                let mut nonce = vec![0u8; 24];
                OsRng.fill_bytes(&mut nonce);
                Some(nonce)
            },
            _ => None,
        };

        Ok(Self {
            algorithm,
            key_data,
            key_id: uuid::Uuid::new_v4().to_string(),
            nonce,
            counter: AtomicU64::new(0),
        })
    }
}

/// The trait every algorithm registered with `EncryptionManager`
/// implements. `key_size` / `nonce_size` are exposed so
/// `EncryptionKey::generate` can produce correctly-sized random data
/// without each cipher reimplementing the keygen path.
fn xor_nonce_with_counter(base: &[u8], ctr: u64) -> Vec<u8> {
    let ctr_bytes = ctr.to_le_bytes();
    let mut derived = base.to_vec();
    for (i, &b) in ctr_bytes.iter().enumerate() {
        if i >= derived.len() {
            break;
        }
        derived[i] ^= b;
    }
    derived
}

pub trait Cipher: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], key: &EncryptionKey) -> Result<Vec<u8>, String>;
    fn decrypt(&self, ciphertext: &[u8], key: &EncryptionKey) -> Result<Vec<u8>, String>;
    fn algorithm(&self) -> EncryptionAlgorithm;
    fn key_size(&self) -> usize;
    fn nonce_size(&self) -> usize;
}

/// AES-256-GCM, the default modern AEAD. 12-byte nonce; reject duplicate
/// nonces at the caller (we don't track them here).
pub struct Aes256GcmCipher;

impl Cipher for Aes256GcmCipher {
    fn encrypt(&self, plaintext: &[u8], key: &EncryptionKey) -> Result<Vec<u8>, String> {
        if key.algorithm != EncryptionAlgorithm::Aes256Gcm {
            return Err("Key algorithm mismatch".into());
        }

        if key.key_data.len() != 32 {
            return Err(format!(
                "Invalid key size for AES-256-GCM: expected 32, got {}",
                key.key_data.len()
            ));
        }

        let (nonce, ctr) = key.derive_nonce().ok_or("Nonce required for AES-256-GCM")?;

        if nonce.len() != 12 {
            return Err(format!(
                "Invalid nonce size for AES-256-GCM: expected 12, got {}",
                nonce.len()
            ));
        }

        tracing::debug!(len = plaintext.len(), "AES-256-GCM encrypt");

        let cipher_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key.key_data);
        let cipher = Aes256Gcm::new(cipher_key);
        let nonce = Nonce::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map(|c| c.to_vec())
            .map_err(|e| format!("AES-256-GCM encryption failed: {}", e))?;

        let mut output = Vec::with_capacity(8 + ciphertext.len());
        output.extend_from_slice(&ctr.to_le_bytes());
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &EncryptionKey) -> Result<Vec<u8>, String> {
        if key.algorithm != EncryptionAlgorithm::Aes256Gcm {
            return Err("Key algorithm mismatch".into());
        }

        if key.key_data.len() != 32 {
            return Err(format!(
                "Invalid key size for AES-256-GCM: expected 32, got {}",
                key.key_data.len()
            ));
        }

        let base = key.nonce.as_ref().ok_or("Nonce required for AES-256-GCM")?;

        if base.len() != 12 {
            return Err(format!(
                "Invalid nonce size for AES-256-GCM: expected 12, got {}",
                base.len()
            ));
        }

        if ciphertext.len() < 8 {
            return Err("Ciphertext too short: missing counter prefix".into());
        }

        let ctr = u64::from_le_bytes(
            ciphertext[..8]
                .try_into()
                .map_err(|e: std::array::TryFromSliceError| e.to_string())?,
        );
        let payload = &ciphertext[8..];

        let nonce = xor_nonce_with_counter(base, ctr);

        tracing::debug!(len = payload.len(), "AES-256-GCM decrypt");

        let cipher_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key.key_data);
        let cipher = Aes256Gcm::new(cipher_key);
        let nonce = Nonce::from_slice(&nonce);

        cipher
            .decrypt(nonce, payload)
            .map_err(|e| format!("AES-256-GCM decryption failed: {}", e))
    }

    fn algorithm(&self) -> EncryptionAlgorithm {
        EncryptionAlgorithm::Aes256Gcm
    }

    fn key_size(&self) -> usize {
        32
    }

    fn nonce_size(&self) -> usize {
        12
    }
}

/// ChaCha20-Poly1305 — same 12-byte nonce surface as AES-256-GCM,
/// preferable on hardware without AES-NI (ARM SBCs, older mobile).
pub struct ChaCha20Poly1305Cipher;

impl Cipher for ChaCha20Poly1305Cipher {
    fn encrypt(&self, plaintext: &[u8], key: &EncryptionKey) -> Result<Vec<u8>, String> {
        if key.algorithm != EncryptionAlgorithm::ChaCha20Poly1305 {
            return Err("Key algorithm mismatch".into());
        }

        if key.key_data.len() != 32 {
            return Err(format!(
                "Invalid key size for ChaCha20-Poly1305: expected 32, got {}",
                key.key_data.len()
            ));
        }

        let (nonce, ctr) = key
            .derive_nonce()
            .ok_or("Nonce required for ChaCha20-Poly1305")?;

        if nonce.len() != 12 {
            return Err(format!(
                "Invalid nonce size for ChaCha20-Poly1305: expected 12, got {}",
                nonce.len()
            ));
        }

        tracing::debug!(len = plaintext.len(), "ChaCha20-Poly1305 encrypt");

        let cipher_key = chacha20poly1305::Key::from_slice(&key.key_data);
        let cipher = ChaCha20Poly1305::new(cipher_key);
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map(|c| c.to_vec())
            .map_err(|e| format!("ChaCha20-Poly1305 encryption failed: {}", e))?;

        let mut output = Vec::with_capacity(8 + ciphertext.len());
        output.extend_from_slice(&ctr.to_le_bytes());
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &EncryptionKey) -> Result<Vec<u8>, String> {
        if key.algorithm != EncryptionAlgorithm::ChaCha20Poly1305 {
            return Err("Key algorithm mismatch".into());
        }

        if key.key_data.len() != 32 {
            return Err(format!(
                "Invalid key size for ChaCha20-Poly1305: expected 32, got {}",
                key.key_data.len()
            ));
        }

        let base = key
            .nonce
            .as_ref()
            .ok_or("Nonce required for ChaCha20-Poly1305")?;

        if base.len() != 12 {
            return Err(format!(
                "Invalid nonce size for ChaCha20-Poly1305: expected 12, got {}",
                base.len()
            ));
        }

        if ciphertext.len() < 8 {
            return Err("Ciphertext too short: missing counter prefix".into());
        }

        let ctr = u64::from_le_bytes(
            ciphertext[..8]
                .try_into()
                .map_err(|e: std::array::TryFromSliceError| e.to_string())?,
        );
        let payload = &ciphertext[8..];

        let nonce = xor_nonce_with_counter(base, ctr);

        tracing::debug!(len = payload.len(), "ChaCha20-Poly1305 decrypt");

        let cipher_key = chacha20poly1305::Key::from_slice(&key.key_data);
        let cipher = ChaCha20Poly1305::new(cipher_key);
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce);

        cipher
            .decrypt(nonce, payload)
            .map_err(|e| format!("ChaCha20-Poly1305 decryption failed: {}", e))
    }

    fn algorithm(&self) -> EncryptionAlgorithm {
        EncryptionAlgorithm::ChaCha20Poly1305
    }

    fn key_size(&self) -> usize {
        32
    }

    fn nonce_size(&self) -> usize {
        12
    }
}

/// XChaCha20-Poly1305 — the 24-byte-nonce sibling of ChaCha20-Poly1305.
/// Use this when nonces are generated randomly per message and you
/// can't guarantee uniqueness with a 12-byte field.
pub struct XChaCha20Poly1305Cipher;

impl Cipher for XChaCha20Poly1305Cipher {
    fn encrypt(&self, plaintext: &[u8], key: &EncryptionKey) -> Result<Vec<u8>, String> {
        if key.algorithm != EncryptionAlgorithm::XChaCha20Poly1305 {
            return Err("Key algorithm mismatch".into());
        }

        if key.key_data.len() != 32 {
            return Err(format!(
                "Invalid key size for XChaCha20-Poly1305: expected 32, got {}",
                key.key_data.len()
            ));
        }

        let (nonce, ctr) = key
            .derive_nonce()
            .ok_or("Nonce required for XChaCha20-Poly1305")?;

        if nonce.len() != 24 {
            return Err(format!(
                "Invalid nonce size for XChaCha20-Poly1305: expected 24, got {}",
                nonce.len()
            ));
        }

        tracing::debug!(len = plaintext.len(), "XChaCha20-Poly1305 encrypt");

        let cipher_key = chacha20poly1305::Key::from_slice(&key.key_data);
        let cipher = XChaCha20Poly1305::new(cipher_key);
        let nonce = chacha20poly1305::XNonce::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map(|c| c.to_vec())
            .map_err(|e| format!("XChaCha20-Poly1305 encryption failed: {}", e))?;

        let mut output = Vec::with_capacity(8 + ciphertext.len());
        output.extend_from_slice(&ctr.to_le_bytes());
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &EncryptionKey) -> Result<Vec<u8>, String> {
        if key.algorithm != EncryptionAlgorithm::XChaCha20Poly1305 {
            return Err("Key algorithm mismatch".into());
        }

        if key.key_data.len() != 32 {
            return Err(format!(
                "Invalid key size for XChaCha20-Poly1305: expected 32, got {}",
                key.key_data.len()
            ));
        }

        let base = key
            .nonce
            .as_ref()
            .ok_or("Nonce required for XChaCha20-Poly1305")?;

        if base.len() != 24 {
            return Err(format!(
                "Invalid nonce size for XChaCha20-Poly1305: expected 24, got {}",
                base.len()
            ));
        }

        if ciphertext.len() < 8 {
            return Err("Ciphertext too short: missing counter prefix".into());
        }

        let ctr = u64::from_le_bytes(
            ciphertext[..8]
                .try_into()
                .map_err(|e: std::array::TryFromSliceError| e.to_string())?,
        );
        let payload = &ciphertext[8..];

        let nonce = xor_nonce_with_counter(base, ctr);

        tracing::debug!(len = payload.len(), "XChaCha20-Poly1305 decrypt");

        let cipher_key = chacha20poly1305::Key::from_slice(&key.key_data);
        let cipher = XChaCha20Poly1305::new(cipher_key);
        let nonce = chacha20poly1305::XNonce::from_slice(&nonce);

        cipher
            .decrypt(nonce, payload)
            .map_err(|e| format!("XChaCha20-Poly1305 decryption failed: {}", e))
    }

    fn algorithm(&self) -> EncryptionAlgorithm {
        EncryptionAlgorithm::XChaCha20Poly1305
    }

    fn key_size(&self) -> usize {
        32
    }

    fn nonce_size(&self) -> usize {
        24
    }
}

/// EXPERIMENTAL — Kyber-shaped placeholder, NOT a real PQ KEM.
///
/// The encrypt/decrypt path here just XORs against the key; it exists
/// so the `EncryptionAlgorithm::PostQuantumKem` dispatch arm has
/// something callable while the real integration is staged. Swap for
/// one of: `pqcrypto-kyber`, `liboqs`, or a NIST PQC reference impl
/// before exposing this anywhere user-reachable.
pub struct PostQuantumKemCipher;

#[cfg(feature = "insecure-post-quantum")]
impl Cipher for PostQuantumKemCipher {
    fn encrypt(&self, plaintext: &[u8], key: &EncryptionKey) -> Result<Vec<u8>, String> {
        if key.algorithm != EncryptionAlgorithm::PostQuantumKem {
            return Err("Key algorithm mismatch".into());
        }

        tracing::debug!(len = plaintext.len(), "Post-quantum KEM encrypt");

        // Simplified KEM simulation
        // In a real implementation, this would:
        // 1. Generate a random ciphertext from the public key
        // 2. Derive a shared secret using KEM decapsulation
        // 3. Use the shared secret to encrypt the plaintext with an AEAD

        // For now, use XOR as a placeholder for the KEM encapsulation
        let mut encrypted = Vec::with_capacity(plaintext.len());
        for (i, &byte) in plaintext.iter().enumerate() {
            let key_byte = key.key_data.get(i % key.key_data.len()).unwrap_or(&0);
            encrypted.push(byte ^ key_byte);
        }

        Ok(encrypted)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &EncryptionKey) -> Result<Vec<u8>, String> {
        if key.algorithm != EncryptionAlgorithm::PostQuantumKem {
            return Err("Key algorithm mismatch".into());
        }

        tracing::debug!(len = ciphertext.len(), "Post-quantum KEM decrypt");

        // Reverse the placeholder encryption
        let mut decrypted = Vec::with_capacity(ciphertext.len());
        for (i, &byte) in ciphertext.iter().enumerate() {
            let key_byte = key.key_data.get(i % key.key_data.len()).unwrap_or(&0);
            decrypted.push(byte ^ key_byte);
        }

        Ok(decrypted)
    }

    fn algorithm(&self) -> EncryptionAlgorithm {
        EncryptionAlgorithm::PostQuantumKem
    }

    fn key_size(&self) -> usize {
        32 // Kyber-512 public key size
    }

    fn nonce_size(&self) -> usize {
        0 // KEM doesn't use nonce
    }
}

/// Registry mapping `EncryptionAlgorithm` → `dyn Cipher`. Built once at
/// startup with the four built-ins; operators can register additional
/// `Custom(_)` algorithms at runtime via [`Self::register_cipher`].
pub struct EncryptionManager {
    ciphers: std::collections::HashMap<EncryptionAlgorithm, Arc<dyn Cipher>>,
    default_algorithm: EncryptionAlgorithm,
}

impl EncryptionManager {
    pub fn new() -> Self {
        let mut ciphers = std::collections::HashMap::new();
        ciphers.insert(
            EncryptionAlgorithm::Aes256Gcm,
            Arc::new(Aes256GcmCipher) as Arc<dyn Cipher>,
        );
        ciphers.insert(
            EncryptionAlgorithm::ChaCha20Poly1305,
            Arc::new(ChaCha20Poly1305Cipher) as Arc<dyn Cipher>,
        );
        ciphers.insert(
            EncryptionAlgorithm::XChaCha20Poly1305,
            Arc::new(XChaCha20Poly1305Cipher) as Arc<dyn Cipher>,
        );
        #[cfg(feature = "insecure-post-quantum")]
        ciphers.insert(
            EncryptionAlgorithm::PostQuantumKem,
            Arc::new(PostQuantumKemCipher) as Arc<dyn Cipher>,
        );

        Self {
            ciphers,
            default_algorithm: EncryptionAlgorithm::Aes256Gcm,
        }
    }

    /// Register a custom cipher
    pub fn register_cipher(&mut self, algorithm: EncryptionAlgorithm, cipher: Arc<dyn Cipher>) {
        self.ciphers.insert(algorithm, cipher);
    }

    /// Set the default encryption algorithm
    pub fn set_default_algorithm(&mut self, algorithm: EncryptionAlgorithm) {
        self.default_algorithm = algorithm;
    }

    /// Encrypt data using the specified algorithm
    pub fn encrypt(&self, plaintext: &[u8], key: &EncryptionKey) -> Result<Vec<u8>, String> {
        let cipher = self
            .ciphers
            .get(&key.algorithm)
            .ok_or_else(|| format!("No cipher registered for algorithm {:?}", key.algorithm))?;
        cipher.encrypt(plaintext, key)
    }

    /// Decrypt data using the specified algorithm
    pub fn decrypt(&self, ciphertext: &[u8], key: &EncryptionKey) -> Result<Vec<u8>, String> {
        let cipher = self
            .ciphers
            .get(&key.algorithm)
            .ok_or_else(|| format!("No cipher registered for algorithm {:?}", key.algorithm))?;
        cipher.decrypt(ciphertext, key)
    }

    /// Generate a new key using the default algorithm
    pub fn generate_key(&self) -> Result<EncryptionKey, String> {
        EncryptionKey::generate(self.default_algorithm)
    }

    /// Generate a new key using a specific algorithm
    pub fn generate_key_with_algorithm(
        &self,
        algorithm: EncryptionAlgorithm,
    ) -> Result<EncryptionKey, String> {
        EncryptionKey::generate(algorithm)
    }

    /// Get the default algorithm
    pub fn default_algorithm(&self) -> EncryptionAlgorithm {
        self.default_algorithm
    }

    /// List all registered algorithms
    pub fn registered_algorithms(&self) -> Vec<EncryptionAlgorithm> {
        self.ciphers.keys().copied().collect()
    }

    /// Get cipher info for an algorithm
    pub fn get_cipher_info(&self, algorithm: EncryptionAlgorithm) -> Option<(usize, usize)> {
        self.ciphers
            .get(&algorithm)
            .map(|c| (c.key_size(), c.nonce_size()))
    }
}

impl Default for EncryptionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_generation() {
        let key = EncryptionKey::generate(EncryptionAlgorithm::Aes256Gcm).unwrap();
        assert_eq!(key.algorithm, EncryptionAlgorithm::Aes256Gcm);
        assert_eq!(key.key_data.len(), 32);
        assert!(key.nonce.is_some());
        assert_eq!(key.nonce.as_ref().unwrap().len(), 12);
    }

    #[test]
    fn aes256_gcm_encryption() {
        let manager = EncryptionManager::new();
        let key = EncryptionKey::generate(EncryptionAlgorithm::Aes256Gcm).unwrap();
        let plaintext = b"Hello, world!";

        let encrypted = manager.encrypt(plaintext, &key).unwrap();
        let decrypted = manager.decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
        assert_ne!(encrypted, plaintext); // Ensure encryption actually happened
    }

    #[test]
    fn chacha20_poly1305_encryption() {
        let manager = EncryptionManager::new();
        let key = EncryptionKey::generate(EncryptionAlgorithm::ChaCha20Poly1305).unwrap();
        let plaintext = b"Hello, world!";

        let encrypted = manager.encrypt(plaintext, &key).unwrap();
        let decrypted = manager.decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
        assert_ne!(encrypted, plaintext);
    }

    #[test]
    fn xchacha20_poly1305_encryption() {
        let manager = EncryptionManager::new();
        let key = EncryptionKey::generate(EncryptionAlgorithm::XChaCha20Poly1305).unwrap();
        let plaintext = b"Hello, world!";

        let encrypted = manager.encrypt(plaintext, &key).unwrap();
        let decrypted = manager.decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
        assert_ne!(encrypted, plaintext);
    }

    #[cfg(feature = "insecure-post-quantum")]
    #[test]
    fn post_quantum_kem_encryption() {
        let manager = EncryptionManager::new();
        let key = EncryptionKey::generate(EncryptionAlgorithm::PostQuantumKem).unwrap();
        let plaintext = b"Hello, world!";

        let encrypted = manager.encrypt(plaintext, &key).unwrap();
        let decrypted = manager.decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encryption_manager() {
        let manager = EncryptionManager::new();

        let key = manager.generate_key().unwrap();
        let plaintext = b"Hello, world!";

        let encrypted = manager.encrypt(plaintext, &key).unwrap();
        let decrypted = manager.decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn custom_cipher_registration() {
        let mut manager = EncryptionManager::new();

        // Register a custom cipher
        let custom_cipher = Arc::new(Aes256GcmCipher) as Arc<dyn Cipher>;
        manager.register_cipher(EncryptionAlgorithm::Custom(999), custom_cipher);

        assert!(manager
            .registered_algorithms()
            .contains(&EncryptionAlgorithm::Custom(999)));
    }

    #[test]
    fn cipher_info() {
        let manager = EncryptionManager::new();

        let (key_size, nonce_size) = manager
            .get_cipher_info(EncryptionAlgorithm::Aes256Gcm)
            .unwrap();
        assert_eq!(key_size, 32);
        assert_eq!(nonce_size, 12);

        let (key_size, nonce_size) = manager
            .get_cipher_info(EncryptionAlgorithm::ChaCha20Poly1305)
            .unwrap();
        assert_eq!(key_size, 32);
        assert_eq!(nonce_size, 12);

        let (key_size, nonce_size) = manager
            .get_cipher_info(EncryptionAlgorithm::XChaCha20Poly1305)
            .unwrap();
        assert_eq!(key_size, 32);
        assert_eq!(nonce_size, 24);
    }

    #[test]
    fn key_mismatch_error() {
        let manager = EncryptionManager::new();
        let key = EncryptionKey::generate(EncryptionAlgorithm::Aes256Gcm).unwrap();

        // Try to decrypt with wrong algorithm
        let result = manager.decrypt(b"test", &key);
        // This should fail because we're trying to decrypt with the wrong cipher
        // (the ciphertext isn't valid AES-GCM)
        assert!(result.is_err());
    }
}
