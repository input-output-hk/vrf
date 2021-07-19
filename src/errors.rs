use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum VrfError {
    #[error("VRF verification failed")]
    VerificationFailed,
    #[error("Decompression failed")]
    DecompressionFailed,
}