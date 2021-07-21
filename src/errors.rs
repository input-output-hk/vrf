//! Crate specific errors
use thiserror::Error;

/// VRF related errors
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum VrfError {
    /// This error occurs when the VRF verification failed
    #[error("VRF verification failed")]
    VerificationFailed,
    /// This error occurs when an `EdwardsPoint` decompression fails
    #[error("Decompression failed")]
    DecompressionFailed,
}
