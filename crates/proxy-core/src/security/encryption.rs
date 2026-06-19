//! Pluggable AEAD cipher registry, plus a post-quantum KEM-DEM hybrid.
//!
//! Minecraft's wire protocol uses AES-128-CFB8 for the Login session
//! key exchange — that's handled in `auth::encryption` and not
//! changeable. This module is for *secondary* encryption: configurable
//! ciphers we use to wrap inter-node communication (cluster gossip,
//! control-plane payloads, etc.) where operators want algorithm agility.
//!
//! The post-quantum option (gated behind the `post-quantum` cargo
//! feature) is a real KEM-DEM hybrid: ML-KEM-768 (the NIST FIPS 203
//! key-encapsulation mechanism, formerly CRYSTALS-Kyber, via the
//! RustCrypto `ml-kem` crate) establishes a 32-byte shared secret which
//! then keys AES-256-GCM for the bulk data. The recipient keypair lives
//! in the [`EncryptionKey`] so the same `Cipher` trait round-trips. It
//! is "hybrid" only in the KEM+DEM sense — it is **not** combined with a
//! classical KEM, so deploy it alongside (not instead of) a classical
//! cipher if you need hybrid PQ/classical security guarantees.

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
    /// Post-quantum hybrid: ML-KEM-768 (FIPS 203) key encapsulation +
    /// AES-256-GCM bulk encryption. Requires the `post-quantum` feature.
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
        // Post-quantum is special: the "key" is an ML-KEM keypair, not raw
        // symmetric bytes, so it has its own generation path.
        if algorithm == EncryptionAlgorithm::PostQuantumKem {
            #[cfg(feature = "post-quantum")]
            {
                return Ok(Self {
                    algorithm,
                    key_data: pq::generate_keypair_bytes(),
                    key_id: uuid::Uuid::new_v4().to_string(),
                    nonce: None,
                    counter: AtomicU64::new(0),
                });
            }
            #[cfg(not(feature = "post-quantum"))]
            {
                return Err("PostQuantumKem requires the `post-quantum` cargo feature".to_string());
            }
        }

        let key_size = match algorithm {
            EncryptionAlgorithm::Aes256Gcm => 32,
            EncryptionAlgorithm::ChaCha20Poly1305 => 32,
            EncryptionAlgorithm::XChaCha20Poly1305 => 32,
            EncryptionAlgorithm::PostQuantumKem => unreachable!("handled above"),
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

/// ML-KEM-768 (FIPS 203) + AES-256-GCM hybrid cipher.
///
/// This is a genuine KEM-DEM construction, not a placeholder:
///
/// * **KEM** — the recipient's ML-KEM-768 encapsulation (public) key is
///   used to `encapsulate` a fresh 32-byte shared secret, producing a
///   KEM ciphertext that only the holder of the matching decapsulation
///   (private) key can open. This is the quantum-resistant part.
/// * **DEM** — that shared secret keys AES-256-GCM, which encrypts the
///   actual payload under a fresh random 96-bit nonce.
///
/// The [`EncryptionKey`] for this algorithm carries the *whole keypair*
/// (see [`pq::generate_keypair_bytes`]): encryption needs the public
/// half, decryption the private half, and keeping both together lets the
/// symmetric `Cipher` trait round-trip without a separate key-exchange
/// API. In a real deployment you would instead distribute only the
/// encapsulation key to senders and keep the decapsulation key private.
///
/// Wire format produced by [`encrypt`](Cipher::encrypt):
/// `[kem_ct_len: u32 BE][kem_ct][nonce: 12][aead_ct]`.
pub struct PostQuantumKemCipher;

#[cfg(feature = "post-quantum")]
mod pq {
    use aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use ml_kem::kem::{Decapsulate, Encapsulate};
    use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
    use rand::rngs::OsRng;
    use rand::RngCore;

    type Kem = MlKem768;
    type Ek = <Kem as KemCore>::EncapsulationKey;
    type Dk = <Kem as KemCore>::DecapsulationKey;

    /// Generate a fresh ML-KEM-768 keypair and pack it as
    /// `[ek_len: u32 BE][ek_bytes][dk_bytes]` for storage in
    /// [`super::EncryptionKey::key_data`].
    pub fn generate_keypair_bytes() -> Vec<u8> {
        let (dk, ek) = Kem::generate(&mut OsRng);
        let ek_bytes = ek.as_bytes();
        let dk_bytes = dk.as_bytes();
        let mut out = Vec::with_capacity(4 + ek_bytes.len() + dk_bytes.len());
        out.extend_from_slice(&(ek_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&ek_bytes);
        out.extend_from_slice(&dk_bytes);
        out
    }

    /// Split packed `key_data` into `(ek_bytes, dk_bytes)`.
    fn split_keypair(key_data: &[u8]) -> Result<(&[u8], &[u8]), String> {
        if key_data.len() < 4 {
            return Err("PQ key_data too short for length prefix".into());
        }
        let ek_len = u32::from_be_bytes(key_data[..4].try_into().unwrap()) as usize;
        let rest = &key_data[4..];
        if rest.len() < ek_len {
            return Err("PQ key_data truncated: encapsulation key".into());
        }
        Ok((&rest[..ek_len], &rest[ek_len..]))
    }

    fn parse_ek(bytes: &[u8]) -> Result<Ek, String> {
        let encoded = ml_kem::Encoded::<Ek>::try_from(bytes)
            .map_err(|_| "invalid ML-KEM encapsulation key length".to_string())?;
        Ok(Ek::from_bytes(&encoded))
    }

    fn parse_dk(bytes: &[u8]) -> Result<Dk, String> {
        let encoded = ml_kem::Encoded::<Dk>::try_from(bytes)
            .map_err(|_| "invalid ML-KEM decapsulation key length".to_string())?;
        Ok(Dk::from_bytes(&encoded))
    }

    pub fn encrypt(plaintext: &[u8], key_data: &[u8]) -> Result<Vec<u8>, String> {
        let (ek_bytes, _dk_bytes) = split_keypair(key_data)?;
        let ek = parse_ek(ek_bytes)?;

        // KEM: encapsulate a fresh shared secret to the recipient's public key.
        let (kem_ct, shared) = ek
            .encapsulate(&mut OsRng)
            .map_err(|_| "ML-KEM encapsulation failed".to_string())?;

        // DEM: AES-256-GCM under the shared secret with a random 96-bit nonce.
        let cipher = Aes256Gcm::new_from_slice(shared.as_slice())
            .map_err(|e| format!("AES-256-GCM key setup failed: {e}"))?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let aead_ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|e| format!("AES-256-GCM encryption failed: {e}"))?;

        let kem_ct = kem_ct.as_slice();
        let mut out = Vec::with_capacity(4 + kem_ct.len() + 12 + aead_ct.len());
        out.extend_from_slice(&(kem_ct.len() as u32).to_be_bytes());
        out.extend_from_slice(kem_ct);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&aead_ct);
        Ok(out)
    }

    pub fn decrypt(ciphertext: &[u8], key_data: &[u8]) -> Result<Vec<u8>, String> {
        let (_ek_bytes, dk_bytes) = split_keypair(key_data)?;
        let dk = parse_dk(dk_bytes)?;

        if ciphertext.len() < 4 {
            return Err("PQ ciphertext too short for length prefix".into());
        }
        let kem_ct_len = u32::from_be_bytes(ciphertext[..4].try_into().unwrap()) as usize;
        let rest = &ciphertext[4..];
        if rest.len() < kem_ct_len + 12 {
            return Err("PQ ciphertext truncated".into());
        }
        let (kem_ct_bytes, tail) = rest.split_at(kem_ct_len);
        let (nonce_bytes, aead_ct) = tail.split_at(12);

        // KEM: recover the shared secret with the private key.
        let kem_ct = ml_kem::Ciphertext::<Kem>::try_from(kem_ct_bytes)
            .map_err(|_| "invalid ML-KEM ciphertext length".to_string())?;
        let shared = dk
            .decapsulate(&kem_ct)
            .map_err(|_| "ML-KEM decapsulation failed".to_string())?;

        // DEM: AES-256-GCM open.
        let cipher = Aes256Gcm::new_from_slice(shared.as_slice())
            .map_err(|e| format!("AES-256-GCM key setup failed: {e}"))?;
        cipher
            .decrypt(Nonce::from_slice(nonce_bytes), aead_ct)
            .map_err(|e| format!("AES-256-GCM decryption failed: {e}"))
    }
}

#[cfg(feature = "post-quantum")]
impl Cipher for PostQuantumKemCipher {
    fn encrypt(&self, plaintext: &[u8], key: &EncryptionKey) -> Result<Vec<u8>, String> {
        if key.algorithm != EncryptionAlgorithm::PostQuantumKem {
            return Err("Key algorithm mismatch".into());
        }
        tracing::debug!(len = plaintext.len(), "ML-KEM-768 + AES-256-GCM encrypt");
        pq::encrypt(plaintext, &key.key_data)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &EncryptionKey) -> Result<Vec<u8>, String> {
        if key.algorithm != EncryptionAlgorithm::PostQuantumKem {
            return Err("Key algorithm mismatch".into());
        }
        tracing::debug!(len = ciphertext.len(), "ML-KEM-768 + AES-256-GCM decrypt");
        pq::decrypt(ciphertext, &key.key_data)
    }

    fn algorithm(&self) -> EncryptionAlgorithm {
        EncryptionAlgorithm::PostQuantumKem
    }

    fn key_size(&self) -> usize {
        // Packed keypair length (length prefix + ML-KEM-768 ek + dk). Not a
        // raw symmetric key — see `pq::generate_keypair_bytes`.
        4 + 1184 + 2400
    }

    fn nonce_size(&self) -> usize {
        0 // The per-message AES-GCM nonce is embedded in the ciphertext.
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
        #[cfg(feature = "post-quantum")]
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

    #[cfg(feature = "post-quantum")]
    #[test]
    fn post_quantum_kem_encryption() {
        let manager = EncryptionManager::new();
        let key = EncryptionKey::generate(EncryptionAlgorithm::PostQuantumKem).unwrap();
        let plaintext = b"Hello, post-quantum world!";

        let encrypted = manager.encrypt(plaintext, &key).unwrap();
        let decrypted = manager.decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
        // The KEM ciphertext + AEAD framing must not leak the plaintext.
        assert_ne!(encrypted, plaintext);
        assert!(encrypted.len() > plaintext.len());
    }

    #[cfg(feature = "post-quantum")]
    #[test]
    fn post_quantum_kem_is_randomized() {
        // Encapsulation draws fresh randomness each call, so two encryptions of
        // the same plaintext under the same keypair must differ — yet both must
        // decrypt back to the original.
        let manager = EncryptionManager::new();
        let key = EncryptionKey::generate(EncryptionAlgorithm::PostQuantumKem).unwrap();
        let plaintext = b"determinism is the enemy of nonce reuse";

        let a = manager.encrypt(plaintext, &key).unwrap();
        let b = manager.encrypt(plaintext, &key).unwrap();
        assert_ne!(a, b, "PQ ciphertexts must be randomized");
        assert_eq!(manager.decrypt(&a, &key).unwrap(), plaintext);
        assert_eq!(manager.decrypt(&b, &key).unwrap(), plaintext);
    }

    #[cfg(feature = "post-quantum")]
    #[test]
    fn post_quantum_wrong_keypair_fails() {
        // A ciphertext produced for one keypair must not decrypt under another.
        let manager = EncryptionManager::new();
        let key1 = EncryptionKey::generate(EncryptionAlgorithm::PostQuantumKem).unwrap();
        let key2 = EncryptionKey::generate(EncryptionAlgorithm::PostQuantumKem).unwrap();
        let encrypted = manager.encrypt(b"secret", &key1).unwrap();
        // ML-KEM decapsulation never "fails" (it returns an implicit-reject
        // secret), so the failure surfaces as an AES-GCM tag mismatch instead.
        assert!(manager.decrypt(&encrypted, &key2).is_err());
    }

    #[cfg(not(feature = "post-quantum"))]
    #[test]
    fn post_quantum_requires_feature() {
        // Without the feature the algorithm is unavailable end-to-end.
        assert!(EncryptionKey::generate(EncryptionAlgorithm::PostQuantumKem).is_err());
        let manager = EncryptionManager::new();
        assert!(!manager
            .registered_algorithms()
            .contains(&EncryptionAlgorithm::PostQuantumKem));
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
