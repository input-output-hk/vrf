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

pub const SUITE: &[u8] = &[4u8];
pub const ONE: &[u8] = &[1u8];
pub const TWO: &[u8] = &[2u8];
pub const THREE: &[u8] = &[3u8];
pub const SECRET_KEY_SIZE: usize = 32;
pub const EXTENDED_KEY_SIZE: usize = 64;
pub const SEED_BYTES: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const PROOF_SIZE: usize = 80;
pub const OUTPUT_SIZE: usize = 64;

pub struct SecretKey([u8; SECRET_KEY_SIZE]);

impl SecretKey {
    pub fn as_bytes(&self) -> &[u8]{
        &self.0
    }

    pub fn from_bytes(bytes: &[u8; SECRET_KEY_SIZE]) -> Self {
        SecretKey(*bytes)
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

pub struct PublicKey(CompressedEdwardsY);

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        self.0.as_bytes()
    }

    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_SIZE]) -> Self {
        PublicKey(CompressedEdwardsY::from_slice(bytes))
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

pub struct VrfProof{
    gamma: EdwardsPoint,
    challenge: Scalar,
    response: Scalar
}

impl VrfProof {
    /// Hash to curve function, following the 03 specification, and the libsodium implementation
    /// with `ONE` as a separator. This one is different to the one implemented in curve25519_dalek
    fn hash_to_curve(public_key: &PublicKey, alpha_string: &[u8]) -> EdwardsPoint {
        let mut hash_input = Vec::with_capacity(2 + PUBLIC_KEY_SIZE + alpha_string.len());
        hash_input.extend_from_slice(SUITE);
        hash_input.extend_from_slice(ONE);
        hash_input.extend_from_slice(public_key.as_bytes());
        hash_input.extend_from_slice(alpha_string);
        EdwardsPoint::hash_from_bytes::<Sha512>(&hash_input)
    }

    fn nonce_generation(secret_extension: [u8; 32], h_point: EdwardsPoint) -> Scalar {
        let mut nonce_gen_input = [0u8; 64];
        let h_bytes = h_point.compress().to_bytes();

        nonce_gen_input[..32].copy_from_slice(&secret_extension);
        nonce_gen_input[32..].copy_from_slice(&h_bytes);

        Scalar::hash_from_bytes::<Sha512>(&nonce_gen_input)
    }

    // todo: we are computing `h.compress()` two times (see above).
    fn compute_challenge(h: &EdwardsPoint, gamma: &EdwardsPoint, announcement_1: &EdwardsPoint, announcement_2: &EdwardsPoint) -> Scalar {
        // we use a scalar of 16 bytes (instead of 32), but store it in 32 bits, as that is what
        // `Scalar::from_bits()` expects.
        let mut scalar_bytes = [0u8; 32];
        let mut challenge_hash = Sha512::new();
        challenge_hash.update(SUITE);
        challenge_hash.update(TWO);
        challenge_hash.update(&h.compress().to_bytes());
        challenge_hash.update(gamma.compress().as_bytes());
        challenge_hash.update(announcement_1.compress().as_bytes());
        challenge_hash.update(announcement_2.compress().as_bytes());

        scalar_bytes[..16].copy_from_slice(&challenge_hash.finalize().as_slice()[..16]);

        Scalar::from_bits(scalar_bytes)
    }

    pub fn to_bytes(&self) -> [u8; PROOF_SIZE] {
        let mut proof = [0u8; PROOF_SIZE];
        proof[..32].copy_from_slice(self.gamma.compress().as_bytes());
        proof[32..48].copy_from_slice(&self.challenge.to_bytes()[..16]);
        proof[48..].copy_from_slice(self.response.as_bytes());

        proof
    }

    fn proof_to_hash(&self) -> [u8; OUTPUT_SIZE] {
        let mut output = [0u8; OUTPUT_SIZE];
        let gamma_cofac = self.gamma.mul_by_cofactor();
        let mut hash = Sha512::new();
        hash.update(SUITE);
        hash.update(THREE);
        hash.update(gamma_cofac.compress().as_bytes());

        output.copy_from_slice(hash.finalize().as_slice());
        output
    }

    pub fn generate(public_key: &PublicKey, secret_key: &SecretKey, alpha_string: &[u8]) -> Self {
        let (secret_scalar, secret_extension) = secret_key.extend();

        let h = Self::hash_to_curve(public_key, alpha_string);
        let gamma = secret_scalar * h;

        // Now we generate the nonce
        let k = Self::nonce_generation(secret_extension, h);

        let announcement_base = k * ED25519_BASEPOINT_POINT;
        let announcement_h = k * h;

        // Now we compute the challenge
        let challenge = Self::compute_challenge(&h, &gamma, &announcement_base, &announcement_h);

        // And finally the response of the sigma protocol
        let response = k + challenge * secret_scalar;
        Self { gamma, challenge, response }
    }

    pub fn verify(&self, public_key: &PublicKey, alpha_string: &[u8]) -> Result<[u8; OUTPUT_SIZE], VrfError> {
        let h = Self::hash_to_curve(public_key, alpha_string);

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
        let challenge = Self::compute_challenge(&h, &self.gamma, &U, &V);

        // todo: we don't need constant time equality checking
        if challenge == self.challenge {
            Ok(self.proof_to_hash())
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

        let false_key = PublicKey(EdwardsPoint::hash_from_bytes::<Sha512>(&[0u8]).compress());
        assert!(vrf_proof.verify(&false_key, &alpha_string).is_err())
    }
}
