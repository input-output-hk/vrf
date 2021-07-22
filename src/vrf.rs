//! This module implements `ECVRF-ED25519-SHA512-Elligator2`, as specified in IETF draft,
//! [version 03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03).
//! The current implementation of this vrf does not follow the latest standard definition.
//! However, the goal of this crate is to be compatible with the VRF implementation over
//! [libsodium](https://github.com/input-output-hk/libsodium). In particular, the differences
//! that completely modify the output of the VRF function are the following:
//! - Computation of the Elligator2 function performs a `bit` modification where it shouldn't,
//!   resulting in a completely different VRF output. [Here](https://github.com/input-output-hk/libsodium/blob/draft-irtf-cfrg-vrf-03/src/libsodium/crypto_vrf/ietfdraft03/convert.c#L84)
//!   we clear the sign bit, when it should be cleared only [here](https://github.com/input-output-hk/libsodium/blob/draft-irtf-cfrg-vrf-03/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L2527).
//!   This does not reduce the security of the scheme, but makes it incompatible with other
//!   implementations.
//! - The latest ietf draft no longer includes the suite_string as an input to the `hash_to_curve`
//!   function. Furthermore, it concatenates a zero byte when computing the `proof_to_hash`
//!   function. These changes can be easily seen in the [diff between version 6 and 7](https://www.ietf.org/rfcdiff?difftype=--hwdiff&url2=draft-irtf-cfrg-vrf-07.txt).
//!
//! To provide compatibility with libsodium's implementation, we rely on a fork. Until this is
//! not resolved, one should not use this crate in production.
#![allow(non_snake_case)]
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;

use super::constants::*;
use super::errors::VrfError;

use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use std::fmt::Debug;
use std::iter;
use std::ops::Neg;

/// Secret key, which is formed by `SEED_SIZE` bytes.
pub struct SecretKey([u8; SEED_SIZE]);

impl SecretKey {
    /// View `SecretKey` as byte array
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert a `SecretKey` into its byte representation
    pub fn to_bytes(&self) -> [u8; SEED_SIZE] {
        self.0
    }

    /// Convert a `SecretKey` from a byte array
    pub fn from_bytes(bytes: &[u8; SEED_SIZE]) -> Self {
        SecretKey(*bytes)
    }

    /// Given a cryptographically secure random number generator `csrng`, this function returns
    /// a random `SecretKey`
    pub fn generate<R>(csrng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let mut seed = [0u8; SEED_SIZE];

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
#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub struct PublicKey(CompressedEdwardsY);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "PublicKey({:?}))", self.0)
    }
}

impl PublicKey {
    /// View the `PublicKey` as bytes
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        self.0.as_bytes()
    }

    /// Convert a `PublicKey` into its byte representation.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.0.to_bytes()
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

    /// Generate a `VrfProof` from an array of bytes with the correct size
    pub fn from_bytes(bytes: &[u8; PROOF_SIZE]) -> Result<Self, VrfError> {
        let gamma = CompressedEdwardsY::from_slice(&bytes[..32])
            .decompress()
            .ok_or(VrfError::DecompressionFailed)?;

        let mut challenge_bytes = [0u8; 32];
        challenge_bytes[..16].copy_from_slice(&bytes[32..48]);
        let challenge = Scalar::from_bits(challenge_bytes);

        let mut response_bytes = [0u8; 32];
        response_bytes.copy_from_slice(&bytes[48..]);
        let response =
            Scalar::from_canonical_bytes(response_bytes).ok_or(VrfError::DecompressionFailed)?;

        Ok(Self {
            gamma,
            challenge,
            response,
        })
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

        let decompressed_pk = public_key
            .0
            .decompress()
            .ok_or(VrfError::DecompressionFailed)?;

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
    fn verify_vrf() {
        let alpha_string = [0u8; 23];
        let secret_key = SecretKey::generate(&mut OsRng);
        let public_key = PublicKey::from(&secret_key);

        let vrf_proof = VrfProof::generate(&public_key, &secret_key, &alpha_string);

        assert!(vrf_proof.verify(&public_key, &alpha_string).is_ok());

        let false_key = PublicKey(EdwardsPoint::hash_from_bytes::<Sha512>(&[0u8]).compress());
        assert!(vrf_proof.verify(&false_key, &alpha_string).is_err())
    }

    #[test]
    fn proof_serialisation() {
        let alpha_string = [0u8; 23];
        let secret_key = SecretKey::generate(&mut OsRng);
        let public_key = PublicKey::from(&secret_key);

        let vrf_proof = VrfProof::generate(&public_key, &secret_key, &alpha_string);
        let serialised_proof = vrf_proof.to_bytes();

        let deserialised_proof = VrfProof::from_bytes(&serialised_proof);
        assert!(deserialised_proof.is_ok());

        assert!(deserialised_proof
            .unwrap()
            .verify(&public_key, &alpha_string)
            .is_ok());
    }

    #[test]
    fn keypair_serialisation() {
        let secret_key = SecretKey::generate(&mut OsRng);
        let public_key = PublicKey::from(&secret_key);

        let serialised_sk = secret_key.to_bytes();
        let deserialised_sk = SecretKey::from_bytes(&serialised_sk);
        let pk_from_ser = PublicKey::from(&deserialised_sk);
        assert_eq!(public_key, pk_from_ser);

        let serialised_pk = public_key.to_bytes();
        let deserialised_pk = PublicKey::from_bytes(&serialised_pk);
        assert_eq!(public_key, deserialised_pk);
    }
}
