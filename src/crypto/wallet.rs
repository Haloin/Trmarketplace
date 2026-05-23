use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use k256::ecdsa::{Signature as ECDSASig, VerifyingKey as ECDSAVerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use subtle::ConstantTimeEq;

pub enum WalletAlgorithm {
    Ed25519,
    Secp256k1,
}

pub struct WalletVerifier;

impl WalletVerifier {
    pub fn generate_challenge() -> Vec<u8> {
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        challenge.to_vec()
    }

    pub fn verify_ed25519(pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        let verifying_key = VerifyingKey::from_bytes(
            pubkey.try_into().map_err(|_| anyhow!("Invalid pubkey length"))?
        ).map_err(|_| anyhow!("Invalid public key"))?;

        let sig = Signature::from_slice(signature)
            .map_err(|_| anyhow!("Invalid signature"))?;

        verifying_key.verify(message, &sig)
            .map_err(|_| anyhow!("Signature verification failed"))
    }

    pub fn verify_secp256k1(pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        let verifying_key = ECDSAVerifyingKey::from_sec1_bytes(pubkey)
            .map_err(|_| anyhow!("Invalid public key"))?;

        let sig = ECDSASig::from_slice(signature)
            .map_err(|_| anyhow!("Invalid signature"))?;

        verifying_key.verify(message, &sig)
            .map_err(|_| anyhow!("Signature verification failed"))
    }

    pub fn verify(algorithm: WalletAlgorithm, pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        match algorithm {
            WalletAlgorithm::Ed25519 => Self::verify_ed25519(pubkey, message, signature),
            WalletAlgorithm::Secp256k1 => Self::verify_secp256k1(pubkey, message, signature),
        }
    }

    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        // Length check is unavoidable for security (cannot compare different lengths in constant time)
        // The actual byte comparison below is constant-time using ct_eq
        if a.len() != b.len() {
            return false;
        }
        a.ct_eq(b).unwrap_u8() == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn generate_test_keypair() -> (SigningKey, VerifyingKey) {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let secret_key = ed25519_dalek::SecretKey::from(secret);
        let signing_key = SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let (signing_key, verifying_key) = generate_test_keypair();

        let message = b"test challenge message";
        let signature = signing_key.sign(message);

        let result = WalletVerifier::verify_ed25519(
            &verifying_key.to_bytes(),
            message,
            &signature.to_bytes(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_ed25519_wrong_key_fails() {
        let (signing_key, _) = generate_test_keypair();
        let (wrong_key, _) = generate_test_keypair();

        let message = b"test message";
        let signature = signing_key.sign(message);

        let result = WalletVerifier::verify_ed25519(
            &wrong_key.verifying_key().to_bytes(),
            message,
            &signature.to_bytes(),
        );
        assert!(result.is_err());
    }
}
