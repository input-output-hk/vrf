//! This module implements `ECVRF-ED25519-SHA512-Elligator2`, as specified in IETF draft. The
//! library provides both,
//! [version 09](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-09),
//! and [version 03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03).
//! However, the goal of this library is to be compatible with the VRF implementation over
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
//! - The Elligator2 function of the latest [hash-to-curve draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11)
//!   is different to that specified in the VRF standard.
//!
//! To provide compatibility with libsodium's implementation (available with the `version03` flag),
//! we rely on a fork of dalek-cryptography, to counter the non-compatible `bit` modification.
#![allow(non_snake_case)]
use crate::{vrf03, vrf09};
use super::constants::*;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};



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
    #[cfg(not(feature = "version09"))]
    #[cfg(feature = "version03")]
    /// Hash to curve function, following the 03 specification.
    // Note that in order to be compatible with the implementation over libsodium, we rely on using
    // a fork of curve25519-dalek.
    fn hash_to_curve(public_key: &PublicKey, alpha_string: &[u8]) -> EdwardsPoint {
        let mut hash_input = Vec::with_capacity(2 + PUBLIC_KEY_SIZE + alpha_string.len());
        hash_input.extend_from_slice(SUITE);
        hash_input.extend_from_slice(ONE);
        hash_input.extend_from_slice(public_key.as_bytes());
        hash_input.extend_from_slice(alpha_string);
        EdwardsPoint::hash_from_bytes::<Sha512>(&hash_input)
    }

    #[cfg(feature = "version09")]
    /// Computing the `hash_to_curve` using try and increment. In order to make the
    /// function always terminate, we bound  the number of tries to 32. If the try
    /// 32 fails, which happens with probability around 1/2^32, we compute the
    /// Elligator mapping. This diverges from the standard: the latter describes
    /// the function with an infinite loop. To avoid infinite loops or possibly
    /// non-terminating functions, we adopt this modification.
    fn hash_to_curve(public_key: &PublicKey, alpha_string: &[u8]) -> EdwardsPoint {
        let mut counter = 0u8;
        let mut hash_input = Vec::with_capacity(4 + PUBLIC_KEY_SIZE + alpha_string.len());
        hash_input.extend_from_slice(SUITE);
        hash_input.extend_from_slice(ONE);
        hash_input.extend_from_slice(public_key.as_bytes());
        hash_input.extend_from_slice(alpha_string);
        hash_input.extend_from_slice(&counter.to_be_bytes());
        hash_input.extend_from_slice(ZERO);

        for _ in 0..32 {
            hash_input[2 + PUBLIC_KEY_SIZE + alpha_string.len()] = counter.to_be_bytes()[0];
            if let Some(result) = CompressedEdwardsY::from_slice(&Sha512::digest(&hash_input)[..32]).decompress() {
                return result.mul_by_cofactor();
            };

            counter += 1;
        }

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

    #[cfg(not(feature = "version09"))]
    #[cfg(feature = "version03")]
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

    #[cfg(feature = "version09")]
    /// Hash points function, following the 09 specification.
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
        challenge_hash.update(ZERO);

        scalar_bytes[..16].copy_from_slice(&challenge_hash.finalize().as_slice()[..16]);

        Scalar::from_bits(scalar_bytes)
    }

    /// Generate a `VrfProof` from an array of bytes with the correct size. This function does not
    /// check the validity of the proof.
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

    #[cfg(not(feature = "version09"))]
    #[cfg(feature = "version03")]
    /// `proof_to_hash` function, following the 03 specification. This computes the output of the VRF
    /// function. In particular, this function computes
    /// SHA512(SUITE || THREE || Gamma)
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

    #[cfg(feature = "version09")]
    /// `proof_to_hash` function, following the 09 specification. This computes the output of the VRF
    /// function. In particular, this function computes
    /// SHA512(SUITE || THREE || Gamma || ZERO)
    fn proof_to_hash(&self) -> [u8; OUTPUT_SIZE] {
        let mut output = [0u8; OUTPUT_SIZE];
        let gamma_cofac = self.gamma.mul_by_cofactor();
        let mut hash = Sha512::new();
        hash.update(SUITE);
        hash.update(THREE);
        hash.update(gamma_cofac.compress().as_bytes());
        hash.update(ZERO);

        output.copy_from_slice(hash.finalize().as_slice());
        output
    }

    /// Generate a new VRF proof following the 03 standard. It proceeds as follows:
    /// - Extend the secret key, into a `secret_scalar` and the `secret_extension`
    /// - Evaluate `hash_to_curve` over PK || alpha_string to get `H`
    /// - Compute `Gamma = secret_scalar *  H`
    /// - Generate a proof of discrete logarithm equality between `PK` and `Gamma` with
    ///   bases `generator` and `H` respectively.
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

        if decompressed_pk.is_small_order() {
            return Err(VrfError::PkSmallOrder);
        }

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
    use rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn verify_vrf() {
        let alpha_string = [0u8; 23];
        let secret_key = SecretKey::generate(&mut ChaCha20Rng::from_seed([0u8; 32]));
        let public_key = PublicKey::from(&secret_key);

        let vrf_proof = VrfProof::generate(&public_key, &secret_key, &alpha_string);

        assert!(vrf_proof.verify(&public_key, &alpha_string).is_ok());

        let false_key = PublicKey(EdwardsPoint::hash_from_bytes::<Sha512>(&[0u8]).compress());
        assert!(vrf_proof.verify(&false_key, &alpha_string).is_err())
    }

    #[test]
    fn proof_serialisation() {
        let alpha_string = [0u8; 23];
        let secret_key = SecretKey::generate(&mut ChaCha20Rng::from_seed([0u8; 32]));
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
        let secret_key = SecretKey::generate(&mut ChaCha20Rng::from_seed([0u8; 32]));
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