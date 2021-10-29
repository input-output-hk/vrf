//! Crate specific constants

#[cfg(not(feature = "default"))]
#[cfg(feature = "version03")]
/// `suite_string` of `ECVRF-ED25519-SHA512-Elligator2` defined [here](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03#section-5.5)
pub const SUITE: &[u8] = &[4u8];
#[cfg(feature = "version09")]
/// `suite_string` of `ECVRF-ED25519-SHA512-TAI` defined [here](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-09#section-5.5)
pub const SUITE: &[u8] = &[3u8];
/// `ZERO` used as a domain separator
pub const ZERO: &[u8] = &[0u8];
/// `ONE` used as a domain separator
pub const ONE: &[u8] = &[1u8];
/// `TWO` used as a domain separator
pub const TWO: &[u8] = &[2u8];
/// `THREE` used as a domain separator
pub const THREE: &[u8] = &[3u8];
/// Byte size of the secret seed
pub const SEED_SIZE: usize = 32;
/// Byte size of the public key
pub const PUBLIC_KEY_SIZE: usize = 32;
/// Byte size of the proof
pub const PROOF_SIZE: usize = 80;
/// Byte size of the output of the VRF function
pub const OUTPUT_SIZE: usize = 64;
