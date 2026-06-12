//! Mojang profile-property signature verification.
//!
//! When a 1.7+ client authenticates via Mojang's `hasJoined` endpoint,
//! the returned `ProfileProperty.signature` is Mojang's **RSA-SHA1 over
//! the property's `value` field** (base64-encoded). The proxy verifies
//! that signature against Mojang's well-known public key
//! ([`mojang_public_key` in `kojacoord-config`]) before trusting the
//! property — anyone with a network MITM could otherwise inject a
//! forged skin (or any other property) into the login flow.
//!
//! Online-mode only: when the proxy runs in offline mode (no Mojang
//! auth happened) there's no signature to check; the caller skips
//! [`verify_property`] entirely.
//!
//! The Mojang public key is a standard X.509 SubjectPublicKeyInfo
//! (the same format `openssl rsa -pubout` produces) so we parse it
//! via `pkcs8::DecodePublicKey` and verify with RSA PKCS#1 v1.5.

use base64::engine::{general_purpose, GeneralPurpose};
use base64::Engine;

/// Tolerant base64 engine: standard charset but accept missing /
/// trailing padding (the Mojang signature blobs and the public-key
/// SPKI string in `default_config.toml` are sometimes shipped
/// without the canonical `==` tail).
const B64: GeneralPurpose = general_purpose::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    general_purpose::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);
use pkcs8::DecodePublicKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::RsaPublicKey;
use sha1::{Digest, Sha1};

use crate::session::ProfileProperty;

#[derive(Debug, thiserror::Error)]
pub enum PropertySigError {
    #[error("property is missing a signature (offline-mode property?)")]
    MissingSignature,
    #[error("mojang public key is malformed: {0}")]
    BadPublicKey(String),
    #[error("base64 decode failed for {0}: {1}")]
    Base64(&'static str, String),
    #[error("RSA verification failed: {0}")]
    RsaVerify(String),
}

/// Parse the base64-encoded X.509 SubjectPublicKeyInfo string that
/// lives in `[ProxyConfig.mojang_public_key]`.
///
/// The string in the default config is the same blob Mojang publishes
/// at <https://sessionserver.mojang.com/session/minecraft/profile> as
/// the "yggdrasil" public key. We accept either the bare base64
/// (no PEM headers) or a full PEM block.
pub fn parse_mojang_public_key(key_str: &str) -> Result<RsaPublicKey, PropertySigError> {
    let trimmed = key_str.trim();
    // Strip PEM headers if present so the DER bytes underneath can be
    // base64-decoded uniformly. `pkcs8::DecodePublicKey::from_public_key_pem`
    // would handle headered input too but the default config carries the
    // header-less form.
    //
    // Additionally drop *all* whitespace AND `=` padding bytes — the
    // string in `default_config.toml` is wrapped with embedded
    // whitespace/newlines from TOML's triple-quoted literal, and the
    // base64 decoder rejects `=` characters anywhere except as a tail
    // pad (offset 735 = the `=` inside the inline TOML key). We strip
    // padding entirely and use `STANDARD_NO_PAD` semantics via the
    // `Indifferent` engine to side-step that whole class of error.
    let payload: String = trimmed
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("")
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .collect();
    let der = B64
        .decode(payload.as_bytes())
        .map_err(|e| PropertySigError::Base64("mojang_public_key", e.to_string()))?;
    RsaPublicKey::from_public_key_der(&der)
        .map_err(|e| PropertySigError::BadPublicKey(e.to_string()))
}

/// Verify a single `ProfileProperty` against Mojang's public key.
///
/// Returns `Ok(())` if the signature is valid OR if the property
/// carries no signature AND `require_signature == false`. Returns an
/// error otherwise. Callers running in online mode pass
/// `require_signature = true`.
///
/// Signature bytes are the **RSA PKCS#1 v1.5 SHA-1 signature** over
/// the UTF-8 bytes of `property.value` — matching what Mojang's
/// `MinecraftSessionService` writes when it issues a signed property
/// (see `com.mojang.authlib.yggdrasil.YggdrasilMinecraftSessionService`).
pub fn verify_property(
    property: &ProfileProperty,
    mojang_key: &RsaPublicKey,
    require_signature: bool,
) -> Result<(), PropertySigError> {
    let Some(sig_b64) = property.signature.as_ref() else {
        if require_signature {
            return Err(PropertySigError::MissingSignature);
        }
        return Ok(());
    };
    let sig = B64
        .decode(sig_b64.as_bytes())
        .map_err(|e| PropertySigError::Base64("signature", e.to_string()))?;

    let mut hasher = Sha1::new();
    hasher.update(property.value.as_bytes());
    let digest = hasher.finalize();

    mojang_key
        .verify(Pkcs1v15Sign::new::<Sha1>(), &digest, &sig)
        .map_err(|e| PropertySigError::RsaVerify(e.to_string()))
}

/// Verify every property on a profile. Short-circuits on the first
/// failure. Returns the count of properties verified (useful for
/// telemetry — typical Mojang profiles have just one `textures`
/// property today but the format allows any number).
pub fn verify_properties(
    properties: &[ProfileProperty],
    mojang_key: &RsaPublicKey,
    require_signature: bool,
) -> Result<usize, PropertySigError> {
    let mut verified = 0usize;
    for prop in properties {
        verify_property(prop, mojang_key, require_signature)?;
        verified += 1;
    }
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    use rsa::pkcs8::EncodePublicKey;
    use rsa::{RsaPrivateKey, RsaPublicKey};

    /// Build a small test keypair on the fly. 1024-bit is unsafe for
    /// real Mojang traffic but plenty for the test surface.
    fn test_keypair() -> (RsaPrivateKey, RsaPublicKey) {
        let mut rng = rand::rngs::OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let pub_key = RsaPublicKey::from(&priv_key);
        (priv_key, pub_key)
    }

    /// Encode the test public key the same way Mojang's
    /// `mojang_public_key` is shipped — base64 X.509 SPKI without PEM
    /// headers — and confirm `parse_mojang_public_key` round-trips.
    #[test]
    fn round_trip_through_parse() {
        let (_priv_key, pub_key) = test_keypair();
        let der = pub_key.to_public_key_der().unwrap();
        let key_str = B64.encode(der.as_bytes());
        let parsed = parse_mojang_public_key(&key_str).expect("test key must parse");
        use rsa::traits::PublicKeyParts;
        assert!(parsed.n().bits() >= 1000);
    }

    /// Offline-mode shim: a property without a signature must succeed
    /// when `require_signature=false` and fail otherwise.
    #[test]
    fn missing_signature_respects_require_flag() {
        let (_priv_key, pub_key) = test_keypair();
        let prop = ProfileProperty {
            name: "textures".to_string(),
            value: "fake-base64".to_string(),
            signature: None,
        };
        assert!(verify_property(&prop, &pub_key, false).is_ok());
        assert!(matches!(
            verify_property(&prop, &pub_key, true),
            Err(PropertySigError::MissingSignature)
        ));
    }

    /// Tampered signature: even a single-byte mutation must fail.
    #[test]
    fn tampered_signature_fails_verification() {
        let (_priv_key, pub_key) = test_keypair();
        let fake_sig = B64.encode(vec![0u8; 128]);
        let prop = ProfileProperty {
            name: "textures".to_string(),
            value: "anything".to_string(),
            signature: Some(fake_sig),
        };
        assert!(matches!(
            verify_property(&prop, &pub_key, true),
            Err(PropertySigError::RsaVerify(_))
        ));
    }

    /// Valid signature: hash + sign + verify the exact same value
    /// bytes and confirm verify_property accepts it.
    #[test]
    fn valid_signature_verifies() {
        let (priv_key, pub_key) = test_keypair();
        let value = "ewogICJ0aW1lc3RhbXAiOjE2MDAwMDAwMDAwMDAKfQ==".to_string();
        let mut hasher = Sha1::new();
        hasher.update(value.as_bytes());
        let digest = hasher.finalize();
        let sig_bytes = priv_key
            .sign(Pkcs1v15Sign::new::<Sha1>(), &digest)
            .expect("sign must succeed");
        let prop = ProfileProperty {
            name: "textures".to_string(),
            value,
            signature: Some(B64.encode(sig_bytes)),
        };
        assert!(verify_property(&prop, &pub_key, true).is_ok());
    }
}
