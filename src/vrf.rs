//! VRF related functions, as specified in IETF draft, version 03.
#![allow(non_snake_case)]

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;

use super::errors::VrfError;

use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use std::iter;
use std::ops::Neg;

const SUITE: &[u8] = &[4u8];
const ONE: &[u8] = &[1u8];
const TWO: &[u8] = &[2u8];
const THREE: &[u8] = &[3u8];
const SECRET_KEY_SIZE: usize = 32;
const SEED_BYTES: usize = 32;
const PUBLIC_KEY_SIZE: usize = 32;
const PROOF_SIZE: usize = 80;
const OUTPUT_SIZE: usize = 64;

/// Secret key, which is formed by `SECRET_KEY_SIZE` bytes.
pub struct SecretKey([u8; SECRET_KEY_SIZE]);

impl SecretKey {
    /// View secret key as byte array
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert a secret key from a byte array
    pub fn from_bytes(bytes: &[u8; SECRET_KEY_SIZE]) -> Self {
        SecretKey(*bytes)
    }

    /// Given a cryptographically secure random number generator `csrng`, this function returns
    /// a random `SecretKey`
    pub fn generate<R>(csrng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let mut seed = [0u8; SEED_BYTES];

        csrng.fill_bytes(&mut seed);
        SecretKey(seed)
    }

    /// Given a `SecretKey`, the `extend` function hashes the secret bytes to generate a secret
    /// scalar, and the `SecretKey` extension (of 32 bytes).
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

/// VRF Public key, which is formed by an Edwards point (in compressed form).
pub struct PublicKey(CompressedEdwardsY);

impl PublicKey {
    /// View the `PublicKey` as bytes
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        self.0.as_bytes()
    }

    /// Generate a `PublicKey` from an array of `PUBLIC_KEY_SIZE` bytes.
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

/// VRF proof, which is formed by an `EdwardsPoint`, and two `Scalar`s
pub struct VrfProof {
    gamma: EdwardsPoint,
    challenge: Scalar,
    response: Scalar,
}

impl VrfProof {
    /// Hash to curve function, following the 03 specification.
    // Note that in order to be compatible with the implementation over libsodium, we rely on using
    // a fork of curve25519-dalek. This is not expected to hold for long, as the implementation
    // of the VRF over libsodium will soon change.
    fn hash_to_curve(public_key: &PublicKey, alpha_string: &[u8]) -> EdwardsPoint {
        let mut hash_input = Vec::with_capacity(2 + PUBLIC_KEY_SIZE + alpha_string.len());
        hash_input.extend_from_slice(SUITE);
        hash_input.extend_from_slice(ONE);
        hash_input.extend_from_slice(public_key.as_bytes());
        hash_input.extend_from_slice(alpha_string);
        EdwardsPoint::hash_from_bytes::<Sha512>(&hash_input)
    }

    /// Nonce generation function, following the 03 specification.
    fn nonce_generation(secret_extension: [u8; 32], compressed_h: CompressedEdwardsY) -> Scalar {
        let mut nonce_gen_input = [0u8; 64];
        let h_bytes = compressed_h.to_bytes();

        nonce_gen_input[..32].copy_from_slice(&secret_extension);
        nonce_gen_input[32..].copy_from_slice(&h_bytes);

        Scalar::hash_from_bytes::<Sha512>(&nonce_gen_input)
    }

    /// Hash points function, following the 03 specification.
    fn compute_challenge(
        compressed_h: &CompressedEdwardsY,
        gamma: &EdwardsPoint,
        announcement_1: &EdwardsPoint,
        announcement_2: &EdwardsPoint,
    ) -> Scalar {
        // we use a scalar of 16 bytes (instead of 32), but store it in 32 bits, as that is what
        // `Scalar::from_bits()` expects.
        let mut scalar_bytes = [0u8; 32];
        let mut challenge_hash = Sha512::new();
        challenge_hash.update(SUITE);
        challenge_hash.update(TWO);
        challenge_hash.update(&compressed_h.to_bytes());
        challenge_hash.update(gamma.compress().as_bytes());
        challenge_hash.update(announcement_1.compress().as_bytes());
        challenge_hash.update(announcement_2.compress().as_bytes());

        scalar_bytes[..16].copy_from_slice(&challenge_hash.finalize().as_slice()[..16]);

        Scalar::from_bits(scalar_bytes)
    }

    /// Convert the proof into its byte representation. As specified in the 03 specification, the
    /// challenge can be represented using only 16 bytes, and therefore use only the first 16
    /// bytes of the `Scalar`.
    pub fn to_bytes(&self) -> [u8; PROOF_SIZE] {
        let mut proof = [0u8; PROOF_SIZE];
        proof[..32].copy_from_slice(self.gamma.compress().as_bytes());
        proof[32..48].copy_from_slice(&self.challenge.to_bytes()[..16]);
        proof[48..].copy_from_slice(self.response.as_bytes());

        proof
    }

    /// Proof to hash function, following the 03 specification. This computes the output of the VRF
    /// function.
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

    /// Generate a new VRF proof
    pub fn generate(public_key: &PublicKey, secret_key: &SecretKey, alpha_string: &[u8]) -> Self {
        let (secret_scalar, secret_extension) = secret_key.extend();

        let h = Self::hash_to_curve(public_key, alpha_string);
        let compressed_h = h.compress();
        let gamma = secret_scalar * h;

        // Now we generate the nonce
        let k = Self::nonce_generation(secret_extension, compressed_h);

        let announcement_base = k * ED25519_BASEPOINT_POINT;
        let announcement_h = k * h;

        // Now we compute the challenge
        let challenge =
            Self::compute_challenge(&compressed_h, &gamma, &announcement_base, &announcement_h);

        // And finally the response of the sigma protocol
        let response = k + challenge * secret_scalar;
        Self {
            gamma,
            challenge,
            response,
        }
    }

    /// Verify VRF function, following the 03 specification.
    pub fn verify(
        &self,
        public_key: &PublicKey,
        alpha_string: &[u8],
    ) -> Result<[u8; OUTPUT_SIZE], VrfError> {
        let h = Self::hash_to_curve(public_key, alpha_string);
        let compressed_h = h.compress();

        let decompressed_pk = match public_key.0.decompress() {
            Some(point) => point,
            None => return Err(VrfError::DecompressionFailed),
        };

        let U = EdwardsPoint::vartime_double_scalar_mul_basepoint(
            &self.challenge.neg(),
            &decompressed_pk,
            &self.response,
        );
        let V = EdwardsPoint::vartime_multiscalar_mul(
            iter::once(self.response).chain(iter::once(self.challenge.neg())),
            iter::once(h).chain(iter::once(self.gamma)),
        );

        // Now we compute the challenge
        let challenge = Self::compute_challenge(&compressed_h, &self.gamma, &U, &V);

        if challenge.to_bytes()[..16] == self.challenge.to_bytes()[..16] {
            Ok(self.proof_to_hash())
        } else {
            Err(VrfError::VerificationFailed)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
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
