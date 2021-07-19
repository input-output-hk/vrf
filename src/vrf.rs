#![allow(non_snake_case)]

use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::traits::VartimeMultiscalarMul;

use super::errors::{VrfError};

use sha2::{Sha512, Digest};
use rand::{CryptoRng, RngCore};
use std::iter;
use std::ops::Neg;

pub const SECRET_KEY_SIZE: usize = 32;
pub const EXTENDED_KEY_SIZE: usize = 64;
pub const SEED_BYTES: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const PROOF_SIZE: usize = 80;
pub const OUTPUT_SIZE: usize = 64;

struct SecretKey([u8; SECRET_KEY_SIZE]);

impl SecretKey {
    pub fn as_bytes(&self) -> &[u8]{
        &self.0
    }

    pub fn generate<R>(csrng: &mut R) -> Self
    where
        R: CryptoRng + RngCore
    {
        let mut seed = [0u8; SEED_BYTES];

        csrng.fill_bytes(&mut seed);
        SecretKey(seed)
    }

    // todo: this can be improved (edc)
    pub fn extend(&self) -> (Scalar, [u8; 32]) {
        let mut h: Sha512 = Sha512::new();
        let mut extended = [0u8; 64];
        let mut secret_key_bytes = [0u8; 32];
        let mut extension = [0u8; 32];

        h.update(self.as_bytes());
        extended.copy_from_slice(&h.finalize().as_slice()[..64]);

        secret_key_bytes.copy_from_slice(&extended[..32]);
        extension.copy_from_slice(&extended[32..]);

        secret_key_bytes[0] &= 248;
        secret_key_bytes[31] &= 127;
        secret_key_bytes[31] |= 64;

        (Scalar::from_bits(secret_key_bytes), extension)

    }
}

struct PublicKey(CompressedEdwardsY);

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl<'a> From<&'a SecretKey> for PublicKey {
    /// Derive a public key from a `SecretKey`.
    fn from(sk: &SecretKey) -> PublicKey {
        let (scalar, _) = sk.extend();
        let point = scalar * ED25519_BASEPOINT_POINT;
        PublicKey(point.compress())
    }
}

struct VrfProof{
    gamma: EdwardsPoint,
    challenge: Scalar,
    response: Scalar
}

impl VrfProof {
    pub fn generate(public_key: &PublicKey, secret_key: &SecretKey, alpha_string: &[u8]) -> Self {
        let (secret_scalar, secret_extension) = secret_key.extend();

        let mut hash_input = Vec::with_capacity(PUBLIC_KEY_SIZE + alpha_string.len());
        hash_input.extend_from_slice(public_key.as_bytes());
        hash_input.extend_from_slice(alpha_string);
        let h = EdwardsPoint::hash_from_bytes::<Sha512>(&hash_input);
        let h_bytes = h.compress().to_bytes();
        let gamma = secret_scalar * h;

        // Now we generate the nonce
        let mut nonce_gen_input = [0u8; 64];
        nonce_gen_input[..32].copy_from_slice(&secret_extension);
        nonce_gen_input[32..].copy_from_slice(&h_bytes);

        let k = Scalar::hash_from_bytes::<Sha512>(&nonce_gen_input);
        let announcement_base = k * ED25519_BASEPOINT_POINT;
        let announcement_h = k * h;

        // Now we compute the challenge
        let mut challenge_hash = Sha512::new();
        challenge_hash.update(&h_bytes);
        challenge_hash.update(gamma.compress().as_bytes());
        challenge_hash.update(announcement_base.compress().as_bytes());
        challenge_hash.update(announcement_h.compress().as_bytes());

        let challenge = Scalar::from_hash(challenge_hash);

        // And finally the response of the sigma protocol
        let response = k + challenge * secret_scalar;
        Self { gamma, challenge, response }
    }

    pub fn verify(&self, public_key: &PublicKey, alpha_string: &[u8]) -> Result<(), VrfError> {
        let mut hash_input = Vec::with_capacity(PUBLIC_KEY_SIZE + alpha_string.len());
        hash_input.extend_from_slice(public_key.as_bytes());
        hash_input.extend_from_slice(alpha_string);
        let h = EdwardsPoint::hash_from_bytes::<Sha512>(&hash_input);
        let h_bytes = h.compress().to_bytes();

        let decompressed_pk = match public_key.0.decompress() {
            Some(point) => point,
            None => return Err(VrfError::DecompressionFailed),
        };

        let U = EdwardsPoint::vartime_double_scalar_mul_basepoint(&self.challenge.neg(), &decompressed_pk, &self.response);
        let V = EdwardsPoint::vartime_multiscalar_mul(
            iter::once(self.response)
                .chain(iter::once(self.challenge.neg())),
            iter::once(h)
                .chain(iter::once(self.gamma))
        );

        // Now we compute the challenge
        let mut challenge_hash = Sha512::new();
        challenge_hash.update(&h_bytes);
        challenge_hash.update(self.gamma.compress().as_bytes());
        challenge_hash.update(U.compress().as_bytes());
        challenge_hash.update(V.compress().as_bytes());

        let challenge = Scalar::from_hash(challenge_hash);

        if challenge == self.challenge {
            Ok(())
        }
        else {
            Err(VrfError::VerificationFailed)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::rngs::OsRng;

    # [test]
    fn verify() {
        let alpha_string = [0u8; 23];
        let secret_key = SecretKey::generate(&mut OsRng);
        let public_key = PublicKey::from(&secret_key);

        let vrf_proof = VrfProof::generate(&public_key, &secret_key, &alpha_string);

        assert!(vrf_proof.verify(&public_key, &alpha_string).is_ok());
    }
}
