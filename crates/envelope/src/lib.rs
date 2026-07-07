//! Diff Envelope Format v1 — E2E credential envelope.
//!
//! Normative spec: `product/specs/0-idea/credential-mvp/envelope-format.md`
//! in the diff monorepo. This implementation must stay byte-compatible with
//! the TypeScript implementation at `app/src/lib/envelope/`. Both are pinned
//! by the shared test vectors (`tests/vectors.json`, a copy of the app's
//! `test-vectors.json`) — update the spec and both implementations together,
//! never one alone.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub const ENVELOPE_VERSION: u32 = 1;
pub const ENVELOPE_ALG: &str = "ECDH-P256+HKDF-SHA256+A256GCM";

const VALUE_AAD: &[u8] = b"diff-envelope-v1.value";
const DEK_AAD: &[u8] = b"diff-envelope-v1.dek";
const WRAP_INFO_PREFIX: &[u8] = b"diff-envelope-v1.wrap";

#[derive(Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// AEAD authentication failed — the envelope was tampered with or the
    /// wrong key was used for a present kid.
    Tamper,
    /// No wrap exists for any key the caller holds.
    NoWrap,
    /// Structural problem: bad encoding, unsupported version/alg, bad lengths.
    Format(String),
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvelopeError::Tamper => write!(f, "AEAD authentication failed"),
            EnvelopeError::NoWrap => write!(f, "no wrap for available keys"),
            EnvelopeError::Format(msg) => write!(f, "envelope format error: {msg}"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

type Result<T> = std::result::Result<T, EnvelopeError>;

/// One recipient wrap. Unknown JSON fields are ignored on parse and unknown
/// `role` values are allowed (forward compatibility with e.g. the future
/// org service key).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvelopeWrap {
    pub kid: String,
    pub role: String,
    /// base64url, 65-byte uncompressed SEC1 ephemeral P-256 public key.
    pub epk: String,
    /// base64url, 12-byte wrap nonce.
    pub n: String,
    /// base64url, AES-256-GCM(KEK, n, DEK) — 48 bytes.
    pub wdek: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    pub v: u32,
    pub alg: String,
    /// base64url, AES-256-GCM(DEK, n, value).
    pub ct: String,
    /// base64url, 12-byte value nonce.
    pub n: String,
    pub wraps: Vec<EnvelopeWrap>,
}

/// A recipient to wrap the DEK to.
#[derive(Clone)]
pub struct Recipient {
    pub kid: String,
    pub role: String,
    /// 65-byte uncompressed SEC1 P-256 public key.
    pub public_key: Vec<u8>,
}

/// A private key the caller holds, identified by the enrollment kid.
pub struct KeyHolder {
    pub kid: String,
    /// 32-byte P-256 scalar.
    pub private_scalar: Vec<u8>,
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| EnvelopeError::Format(format!("bad base64url: {e}")))
}

fn parse_public_key(sec1: &[u8]) -> Result<PublicKey> {
    if sec1.len() != 65 || sec1[0] != 0x04 {
        return Err(EnvelopeError::Format(
            "public key must be 65-byte uncompressed SEC1".into(),
        ));
    }
    PublicKey::from_sec1_bytes(sec1)
        .map_err(|_| EnvelopeError::Format("invalid P-256 point".into()))
}

fn parse_secret_key(scalar: &[u8]) -> Result<SecretKey> {
    SecretKey::from_slice(scalar).map_err(|_| EnvelopeError::Format("invalid P-256 scalar".into()))
}

fn public_key_bytes(secret: &SecretKey) -> Vec<u8> {
    secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

/// KEK = HKDF-SHA256(ikm = ECDH x-coord, salt = empty,
///                   info = "diff-envelope-v1.wrap" || 0x00 || epk || recipient_pub)
fn derive_kek(
    secret: &SecretKey,
    peer: &PublicKey,
    epk_bytes: &[u8],
    recipient_pub: &[u8],
) -> [u8; 32] {
    let shared = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    let mut info =
        Vec::with_capacity(WRAP_INFO_PREFIX.len() + 1 + epk_bytes.len() + recipient_pub.len());
    info.extend_from_slice(WRAP_INFO_PREFIX);
    info.push(0);
    info.extend_from_slice(epk_bytes);
    info.extend_from_slice(recipient_pub);
    let hk = Hkdf::<Sha256>::new(None, shared.raw_secret_bytes());
    let mut kek = [0u8; 32];
    hk.expand(&info, &mut kek)
        .expect("32 bytes is a valid HKDF length");
    kek
}

fn aes_gcm_encrypt(key: &[u8; 32], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != 12 {
        return Err(EnvelopeError::Format("nonce must be 12 bytes".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| EnvelopeError::Format("encryption failed".into()))
}

fn aes_gcm_decrypt(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != 12 {
        return Err(EnvelopeError::Format("nonce must be 12 bytes".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| EnvelopeError::Tamper)
}

/// Material for one deterministic wrap (test vectors only).
pub struct WrapMaterial {
    /// 32-byte ephemeral P-256 scalar.
    pub ephemeral_scalar: Vec<u8>,
    /// 12-byte wrap nonce.
    pub nonce: Vec<u8>,
}

fn wrap_dek(
    dek: &[u8; 32],
    recipient: &Recipient,
    material: Option<&WrapMaterial>,
) -> Result<EnvelopeWrap> {
    let (ephemeral, nonce) = match material {
        Some(m) => (parse_secret_key(&m.ephemeral_scalar)?, m.nonce.clone()),
        None => {
            let mut nonce = vec![0u8; 12];
            OsRng.fill_bytes(&mut nonce);
            (SecretKey::random(&mut OsRng), nonce)
        }
    };
    let epk_bytes = public_key_bytes(&ephemeral);
    let recipient_pub = parse_public_key(&recipient.public_key)?;
    let kek = derive_kek(
        &ephemeral,
        &recipient_pub,
        &epk_bytes,
        &recipient.public_key,
    );
    let wdek = aes_gcm_encrypt(&kek, &nonce, dek, DEK_AAD)?;
    Ok(EnvelopeWrap {
        kid: recipient.kid.clone(),
        role: recipient.role.clone(),
        epk: b64(&epk_bytes),
        n: b64(&nonce),
        wdek: b64(&wdek),
    })
}

/// Encrypt a value to one or more recipients with fresh random material.
pub fn seal(value: &[u8], recipients: &[Recipient]) -> Result<Envelope> {
    let mut dek = [0u8; 32];
    OsRng.fill_bytes(&mut dek);
    let mut nonce = vec![0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    seal_with_material(value, recipients, &dek, &nonce, None)
}

/// Deterministic seal used by `seal` and the shared test vectors. Production
/// callers use `seal`.
pub fn seal_with_material(
    value: &[u8],
    recipients: &[Recipient],
    dek: &[u8; 32],
    value_nonce: &[u8],
    per_wrap: Option<&[WrapMaterial]>,
) -> Result<Envelope> {
    if recipients.is_empty() {
        return Err(EnvelopeError::Format(
            "at least one recipient required".into(),
        ));
    }
    let ct = aes_gcm_encrypt(dek, value_nonce, value, VALUE_AAD)?;
    let mut wraps = Vec::with_capacity(recipients.len());
    for (i, recipient) in recipients.iter().enumerate() {
        wraps.push(wrap_dek(dek, recipient, per_wrap.map(|m| &m[i]))?);
    }
    Ok(Envelope {
        v: ENVELOPE_VERSION,
        alg: ENVELOPE_ALG.to_string(),
        ct: b64(&ct),
        n: b64(value_nonce),
        wraps,
    })
}

fn validate(envelope: &Envelope) -> Result<()> {
    if envelope.v != ENVELOPE_VERSION {
        return Err(EnvelopeError::Format(format!(
            "unsupported version {}",
            envelope.v
        )));
    }
    if envelope.alg != ENVELOPE_ALG {
        return Err(EnvelopeError::Format(format!(
            "unsupported alg {}",
            envelope.alg
        )));
    }
    if envelope.wraps.is_empty() {
        return Err(EnvelopeError::Format("missing wraps".into()));
    }
    Ok(())
}

/// Unwrap the DEK with the holder's private key.
pub fn unwrap_dek(envelope: &Envelope, holder: &KeyHolder) -> Result<[u8; 32]> {
    validate(envelope)?;
    let wrap = envelope
        .wraps
        .iter()
        .find(|w| w.kid == holder.kid)
        .ok_or(EnvelopeError::NoWrap)?;
    let secret = parse_secret_key(&holder.private_scalar)?;
    let holder_pub = public_key_bytes(&secret);
    let epk_bytes = unb64(&wrap.epk)?;
    let epk = parse_public_key(&epk_bytes)?;
    let kek = derive_kek(&secret, &epk, &epk_bytes, &holder_pub);
    let dek = aes_gcm_decrypt(&kek, &unb64(&wrap.n)?, &unb64(&wrap.wdek)?, DEK_AAD)?;
    dek.try_into()
        .map_err(|_| EnvelopeError::Format("unwrapped DEK is not 32 bytes".into()))
}

/// Decrypt the value with the holder's private key.
pub fn open(envelope: &Envelope, holder: &KeyHolder) -> Result<Vec<u8>> {
    let dek = unwrap_dek(envelope, holder)?;
    aes_gcm_decrypt(&dek, &unb64(&envelope.n)?, &unb64(&envelope.ct)?, VALUE_AAD)
}

/// Append wraps for additional recipients without re-encrypting the value.
/// Existing kids are skipped (idempotent).
pub fn add_wraps(
    envelope: &Envelope,
    holder: &KeyHolder,
    recipients: &[Recipient],
) -> Result<Envelope> {
    let dek = unwrap_dek(envelope, holder)?;
    let mut out = envelope.clone();
    for recipient in recipients {
        if out.wraps.iter().any(|w| w.kid == recipient.kid) {
            continue;
        }
        out.wraps.push(wrap_dek(&dek, recipient, None)?);
    }
    Ok(out)
}

/// Generate a recipient keypair: (32-byte private scalar, 65-byte SEC1 public).
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let secret = SecretKey::random(&mut OsRng);
    let public = public_key_bytes(&secret);
    (secret.to_bytes().to_vec(), public)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipient(kid: &str, role: &str) -> (Recipient, KeyHolder) {
        let (scalar, public) = generate_keypair();
        (
            Recipient {
                kid: kid.into(),
                role: role.into(),
                public_key: public,
            },
            KeyHolder {
                kid: kid.into(),
                private_scalar: scalar,
            },
        )
    }

    #[test]
    fn round_trips_single_recipient() {
        let (r, h) = recipient("device-1", "device");
        let envelope = seal(b"sk_live_secret", &[r]).unwrap();
        assert_eq!(open(&envelope, &h).unwrap(), b"sk_live_secret");
    }

    #[test]
    fn round_trips_multiple_recipients() {
        let (r1, h1) = recipient("device-1", "device");
        let (r2, h2) = recipient("recovery-1", "recovery");
        let envelope = seal(b"value", &[r1, r2]).unwrap();
        assert_eq!(open(&envelope, &h1).unwrap(), b"value");
        assert_eq!(open(&envelope, &h2).unwrap(), b"value");
    }

    #[test]
    fn fresh_material_per_seal() {
        let (r, _) = recipient("device-1", "device");
        let e1 = seal(b"same", std::slice::from_ref(&r)).unwrap();
        let e2 = seal(b"same", &[r]).unwrap();
        assert_ne!(e1.ct, e2.ct);
        assert_ne!(e1.wraps[0].wdek, e2.wraps[0].wdek);
    }

    #[test]
    fn no_wrap_for_unknown_kid() {
        let (r, _) = recipient("device-1", "device");
        let (_, other) = recipient("device-2", "device");
        let envelope = seal(b"value", &[r]).unwrap();
        assert_eq!(open(&envelope, &other).unwrap_err(), EnvelopeError::NoWrap);
    }

    #[test]
    fn wrong_key_for_known_kid_is_tamper() {
        let (r, _) = recipient("device-1", "device");
        let (_, impostor) = recipient("device-1", "device");
        let envelope = seal(b"value", &[r]).unwrap();
        assert_eq!(
            open(&envelope, &impostor).unwrap_err(),
            EnvelopeError::Tamper
        );
    }

    #[test]
    fn tampered_ct_detected() {
        let (r, h) = recipient("device-1", "device");
        let mut envelope = seal(b"value", &[r]).unwrap();
        let mut ct = unb64(&envelope.ct).unwrap();
        ct[0] ^= 0xff;
        envelope.ct = b64(&ct);
        assert_eq!(open(&envelope, &h).unwrap_err(), EnvelopeError::Tamper);
    }

    #[test]
    fn add_wraps_preserves_ct_and_is_idempotent() {
        let (r1, h1) = recipient("device-1", "device");
        let (r2, h2) = recipient("org-admin-1", "org_admin");
        let envelope = seal(b"value", &[r1.clone()]).unwrap();
        let promoted = add_wraps(&envelope, &h1, &[r2, r1]).unwrap();
        assert_eq!(promoted.ct, envelope.ct);
        assert_eq!(promoted.n, envelope.n);
        assert_eq!(promoted.wraps.len(), 2);
        assert_eq!(open(&promoted, &h2).unwrap(), b"value");
    }

    #[test]
    fn rejects_unsupported_version() {
        let (r, h) = recipient("device-1", "device");
        let mut envelope = seal(b"value", &[r]).unwrap();
        envelope.v = 2;
        assert!(matches!(
            open(&envelope, &h).unwrap_err(),
            EnvelopeError::Format(_)
        ));
    }
}
