use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::crypto::zk::constant_time_compare;

type HmacSha256 = Hmac<Sha256>;

/// Derive an HMAC auth key from the server secret and a user's pubkey.
/// Used by both the challenge/auth service and the stateless auth middleware.
pub fn derive_auth_key(server_secret: &str, pubkey: &[u8]) -> Option<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(server_secret.as_bytes()).ok()?;
    mac.update(b"auth_key_derivation_v1");
    mac.update(pubkey);
    Some(mac.finalize().into_bytes().to_vec())
}

/// Derive an ephemeral admin identity for a specific session/action domain.
/// Each session gets a different identity, preventing action linkability.
/// The server cannot determine which admin identity was used for which action.
pub fn derive_ephemeral_admin_identity(
    server_secret: &str,
    session_nonce: &[u8],
    action_domain: &str,
) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(server_secret.as_bytes())
        .expect("HMAC key derivation must not fail");
    mac.update(b"ephemeral-admin-identity-v1");
    mac.update(action_domain.as_bytes());
    mac.update(session_nonce);
    mac.finalize().into_bytes().to_vec()
}

/// Verify an ephemeral admin identity for a specific action domain.
/// Returns true if the identity was derived from the server secret.
pub fn verify_ephemeral_admin_identity(
    server_secret: &str,
    identity: &[u8],
    session_nonce: &[u8],
    action_domain: &str,
) -> bool {
    let expected = derive_ephemeral_admin_identity(server_secret, session_nonce, action_domain);
    constant_time_compare(&expected, identity)
}

#[derive(Clone, Debug)]
pub struct AuthPubkey(pub Vec<u8>);

/// The full 32-byte ed25519 public key of the authenticated requester.
/// Distinct from `AuthPubkey` (which is the hash used for cheap equality
/// checks). Handlers that need to verify ed25519 signatures (e.g. state
/// transition signatures) use this.
#[derive(Clone, Debug)]
pub struct AuthPubkeyBytes(pub [u8; 32]);
